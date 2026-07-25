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
# This reimplements that walk: frame sizes come from LLVM and the call graph
# comes from the call relocations, so the number printed is the one the verifier
# will compute rather than an estimate.

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
type -p "${readobj}" >/dev/null 2>&1 || readobj=llvm-readobj-17
readelf=llvm-readelf
type -p "${readelf}" >/dev/null 2>&1 || readelf=llvm-readelf-17
objdump=llvm-objdump
type -p "${objdump}" >/dev/null 2>&1 || objdump=llvm-objdump-17

# MAX_BPF_STACK from include/linux/filter.h.
readonly max_bpf_stack=512
# Granularity the verifier rounds every frame up to.
readonly frame_align=32
# MAX_CALL_FRAMES from include/linux/bpf.h.
readonly max_call_frames=8

# LLVM knows the exact frame size of each function, so ask it rather than
# guessing from the disassembly. -stack-size-section is emitted into a separate
# object so the shipped blob stays byte for byte identical.
tmpobj="$(mktemp --suffix=-stacksizes.o)"
trap 'rm -f "${tmpobj}"' EXIT
"${LLC}" -march=bpf -mcpu="${mcpu}" -filetype=obj -stack-size-section \
  "${bitcode}" -o "${tmpobj}"

# Function -> section, start offset and length. objdump prints, per symbol:
#   0000000000000000 g     F .text  0000000000000128 unwind_native
declare -A section_of start_of end_of
while read -r name section start size; do
  section_of["${name}"]="${section}"
  start_of["${name}"]=$((16#${start}))
  end_of["${name}"]=$((16#${start} + 16#${size}))
done < <("${objdump}" --syms "${tmpobj}" |
  awk '/[[:space:]]F[[:space:]]/ { print $NF, $(NF-2), $1, $(NF-1) }')

# llvm-readobj --stack-sizes prints, per function:
#   Entry {
#     Functions: [unwind_native]
#     Size: 0x80
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

# Call graph. A bpf-to-bpf call is emitted as `call -1` plus an R_BPF_64_32
# relocation naming the callee, so the edges live in the relocation table rather
# than the disassembly. R_BPF_64_64 relocations that name a function are the
# other kind of edge: a callback handed to a helper such as bpf_find_vma, which
# the verifier also walks into. Attribute each to the function whose extent
# contains it.
declare -A callees_of
while read -r section offset_hex symbol; do
  [[ -n "${size_of[${symbol}]+x}" ]] || continue
  offset=$((16#${offset_hex}))
  for caller in "${!section_of[@]}"; do
    [[ "${section_of[${caller}]}" == "${section}" ]] || continue
    ((offset >= start_of[${caller}] && offset < end_of[${caller}])) || continue
    [[ " ${callees_of[${caller}]:-} " == *" ${symbol} "* ]] ||
      callees_of["${caller}"]="${callees_of[${caller}]:-}${symbol} "
    break
  done
done < <("${readelf}" --relocations "${tmpobj}" | awk '
  /^Relocation section/ { sec=$3; gsub(/\x27/,"",sec); sub(/^\.rel/,"",sec); next }
  NF >= 5 && ($3 == "R_BPF_64_32" || $3 == "R_BPF_64_64") { print sec, $1, $NF }')

round_up() { echo $(((($1 + frame_align - 1) / frame_align) * frame_align)); }

# Helper callbacks (bpf_find_vma's, bpf_loop's) are local symbols whose address
# is taken, so their relocation names the enclosing section rather than the
# function and the loop above cannot see the edge. A local .text function that no
# relocation names is exactly that case - an unreferenced local would have been
# dropped by the compiler. The verifier walks into callbacks too, so charge the
# largest of them to every chain.
callback_cost=0
callback_fn=""
for fn in "${!size_of[@]}"; do
  [[ "${section_of[${fn}]:-?}" == ".text" ]] || continue
  referenced=0
  for caller in "${!callees_of[@]}"; do
    [[ " ${callees_of[${caller}]} " == *" ${fn} "* ]] && referenced=1 && break
  done
  ((referenced)) && continue
  cost="$(round_up "${size_of[${fn}]}")"
  if ((cost > callback_cost)); then
    callback_cost="${cost}"
    callback_fn="${fn}"
  fi
done

# Deepest chain starting at $1, as "<total stack> <frames> <path>".
declare -A memo
worst_chain_from() {
  local fn="$1" seen="$2"
  if [[ " ${seen} " == *" ${fn} "* ]]; then
    echo "0 0 (recursion into ${fn})"
    return
  fi
  if [[ -n "${memo[${fn}]+x}" ]]; then
    echo "${memo[${fn}]}"
    return
  fi

  local own_cost best_extra=0 best_frames=0 best_path="" callee result
  own_cost="$(round_up "${size_of[${fn}]:-0}")"
  for callee in ${callees_of[${fn}]:-}; do
    result="$(worst_chain_from "${callee}" "${seen} ${fn}")"
    local extra="${result%% *}" rest="${result#* }"
    local frames="${rest%% *}" path="${rest#* }"
    if ((extra > best_extra)); then
      best_extra="${extra}"
      best_frames="${frames}"
      best_path="${path}"
    fi
  done

  local total=$((own_cost + best_extra))
  local chain="${fn} (${size_of[${fn}]:-0})"
  [[ -n "${best_path}" ]] && chain="${chain} -> ${best_path}"
  memo["${fn}"]="${total} $((best_frames + 1)) ${chain}"
  echo "${memo[${fn}]}"
}

echo
echo "Stack usage for ${bitcode} (${max_bpf_stack} bytes shared across the call chain):"
echo

report=""
for fn in "${!size_of[@]}"; do
  section="${section_of[${fn}]:-?}"
  label="[global function]"
  [[ "${section}" == ".text" ]] || label="[${section}]"
  report+="$(printf '  %5d  %-40s %s' "${size_of[${fn}]}" "${fn}" "${label}")"$'\n'
done
printf '%s' "${report}" | sort -rn

# Only entry points start a chain; a global function is never the root of one.
worst_total=0
worst_frames=0
worst_chain=""
for fn in "${!size_of[@]}"; do
  [[ "${section_of[${fn}]:-?}" != ".text" ]] || continue
  result="$(worst_chain_from "${fn}" "")"
  total="${result%% *}"
  rest="${result#* }"
  frames="${rest%% *}"
  if ((total > worst_total)); then
    worst_total="${total}"
    worst_frames="${frames}"
    worst_chain="${rest#* }"
  fi
done

if ((callback_cost > 0)); then
  worst_total=$((worst_total + callback_cost))
  worst_frames=$((worst_frames + 1))
  worst_chain="${worst_chain} -> ${callback_fn} (${size_of[${callback_fn}]}, helper callback)"
fi

echo
echo "  deepest chain (${worst_frames} frames, ${worst_total} bytes):"
echo "    ${worst_chain}"
echo

status=0
if ((worst_total > max_bpf_stack)); then
  echo "  ERROR: ${worst_total} bytes exceeds MAX_BPF_STACK (${max_bpf_stack})." >&2
  echo "  The verifier will reject this with \"combined stack size of N calls is" >&2
  echo "  ${worst_total}. Too large\". Move locals into the PerCPURecord scratch union." >&2
  status=1
fi
if ((worst_frames > max_call_frames)); then
  echo "  ERROR: ${worst_frames} nested calls exceeds MAX_CALL_FRAMES (${max_call_frames})." >&2
  status=1
fi
exit "${status}"
