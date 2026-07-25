#!/usr/bin/env bash
#
# Reports the stack usage of every function in the linked tracer and fails the
# build when the worst case call chain no longer fits the kernel's budget.
#
# The verifier accounts for stack across an entire bpf-to-bpf call chain rather
# than per function. check_max_stack_depth() in kernel/bpf/verifier.c walks the
# call graph accumulating
#
#     depth += round_up(max_t(u32, subprog[idx].stack_depth, 1), 32);
#     if (depth > MAX_BPF_STACK)   /* 512 */
#             ... "combined stack size of %d calls is %d. Too large"
#
# so a 300 byte function calling another 300 byte function is rejected even
# though neither exceeds the limit on its own. Tail call targets used to dodge
# this because each one is a separate program that starts the walk from zero;
# the unwinders are global functions now and no longer do.
#
# The unwinders are arranged so the deepest chain is two frames: an entry
# program with the dispatch loop inlined, calling one global function. The check
# below therefore pairs the largest entry program with the largest global
# function. Keep that shape - a global function calling another global function
# adds a third frame that this check would not account for.

set -eu
set -o pipefail

readonly bitcode="${1:-}"
readonly mcpu="${2:-v2}"
if [[ -z "${bitcode}" ]]; then
  echo "usage: $0 <linked-bitcode> [mcpu]" >&2
  exit 1
fi

LLC="${LLC:-llc-17}"

readobj=llvm-readobj
type -p "${readobj}" >/dev/null || readobj=llvm-readobj-17
objdump=llvm-objdump
type -p "${objdump}" >/dev/null || objdump=llvm-objdump-17

# MAX_BPF_STACK from include/linux/filter.h.
readonly max_bpf_stack=512
# Granularity the verifier rounds every frame up to.
readonly frame_align=32

# LLVM knows the exact frame size of each function, so ask it rather than
# guessing from the disassembly. -stack-size-section is emitted into a separate
# object so the shipped blob stays byte for byte identical.
tmpobj="$(mktemp --suffix=-stacksizes.o)"
trap 'rm -f "${tmpobj}"' EXIT
"${LLC}" -march=bpf -mcpu="${mcpu}" -filetype=obj -stack-size-section \
  "${bitcode}" -o "${tmpobj}"

# Function name -> section it lives in. Global functions land in .text, entry
# points land in their SEC() section.
declare -A section_of
while read -r name section; do
  section_of["${name}"]="${section}"
done < <("${objdump}" --syms "${tmpobj}" |
  awk '/[[:space:]]F[[:space:]]/ { print $NF, $(NF-2) }')

# llvm-readobj --stack-sizes prints, per function:
#   Entry {
#     Functions: [name]
#     Size: 0x130
#   }
declare -A size_of
fn=""
while read -r key value; do
  case "${key}" in
  Functions:) fn="${value}" ;;
  Size:) [[ -n "${fn}" ]] && size_of["${fn}"]=$((value)) && fn="" ;;
  esac
done < <("${readobj}" --stack-sizes "${tmpobj}" |
  awk '/Functions: \[/ { n=$0; sub(/.*\[/,"",n); sub(/\].*/,"",n); print "Functions:", n }
       /Size: /        { print "Size:", $2 }')

round_up() { echo $(((($1 + frame_align - 1) / frame_align) * frame_align)); }

worst_entry=0
worst_entry_fn="(none)"
worst_global=0
worst_global_fn="(none)"

echo
echo "Stack usage for ${bitcode} (${max_bpf_stack} bytes shared across the call chain):"
echo

report=""
for fn in "${!size_of[@]}"; do
  size="${size_of[${fn}]}"
  section="${section_of[${fn}]:-?}"
  if [[ "${section}" == ".text" ]]; then
    report+="$(printf '  %5d  %-40s [global function]' "${size}" "${fn}")"$'\n'
    if ((size > worst_global)); then
      worst_global="${size}"
      worst_global_fn="${fn}"
    fi
  else
    report+="$(printf '  %5d  %-40s [%s]' "${size}" "${fn}" "${section}")"$'\n'
    if ((size > worst_entry)); then
      worst_entry="${size}"
      worst_entry_fn="${fn}"
    fi
  fi
done
printf '%s' "${report}" | sort -rn

entry_cost="$(round_up "${worst_entry}")"
global_cost="$(round_up "${worst_global}")"
total=$((entry_cost + global_cost))

echo
echo "  worst case chain: ${worst_entry_fn} (${worst_entry} -> ${entry_cost})" \
  "+ ${worst_global_fn} (${worst_global} -> ${global_cost}) = ${total}"

if ((total > max_bpf_stack)); then
  echo
  echo "  ERROR: ${total} bytes exceeds MAX_BPF_STACK (${max_bpf_stack})." \
    "The verifier will reject this with" >&2
  echo "  \"combined stack size of N calls is ${total}. Too large\"." \
    "Move locals into the PerCPURecord" >&2
  echo "  scratch union, or reduce the number of frames unwound per call." >&2
  echo
  exit 1
fi

echo
