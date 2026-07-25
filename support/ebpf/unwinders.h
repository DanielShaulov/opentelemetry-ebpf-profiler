// Declarations of the unwinders and the loop that drives them.
//
// Unwinding used to be a chain of tail calls: every unwinder ended by tail
// calling whichever unwinder should handle the next frame, and the final one
// tail called PROG_UNWIND_STOP to report the trace. Each hop cost a program
// array lookup and a full re-entry into the BPF program, the chain length was
// capped by the kernel's 33 tail call limit, and none of the unwinders could be
// read without knowing which program the array happened to hold at that index.
//
// The unwinders are BPF global functions now. Each one processes some frames
// and returns the id of the unwinder that should run next, and the entry
// programs run unwind_loop() below until an unwinder returns PROG_UNWIND_STOP.
//
// What makes this fit in one program is that the verifier checks a global
// function once, on its own, instead of re-walking it at every call site
// (function-by-function verification, Linux 5.6+). Only the loop body's dozen
// or so instructions are multiplied by the iteration count, not the bodies of
// the unwinders.
//
// The verifier knowing nothing about the caller is also what shapes the
// signature. Global function arguments may only be scalars or a pointer to the
// program context, and on 5.10 a context pointer has to match the program type
// exactly, which rules out sharing one unwinder between the perf event and
// kprobe entry points. So the unwinders take no context at all: they receive
// the index of the per-CPU record holding the trace and look it up themselves.
// Anything that genuinely needs the context - bpf_perf_event_output for the PID
// notification - stays in the entry program.

#ifndef OPTI_UNWINDERS_H
#define OPTI_UNWINDERS_H

#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

// Each unwinder unwinds some frames of the trace in per-CPU record rec_idx and
// returns the TracePrograms id of the unwinder to run next, or PROG_UNWIND_STOP
// when the trace is complete.
EBPF_GLOBAL int unwind_native(u32 rec_idx);
EBPF_GLOBAL int unwind_hotspot(u32 rec_idx);
EBPF_GLOBAL int unwind_perl(u32 rec_idx);
EBPF_GLOBAL int unwind_python(u32 rec_idx);
EBPF_GLOBAL int unwind_php(u32 rec_idx);
EBPF_GLOBAL int unwind_ruby(u32 rec_idx);
EBPF_GLOBAL int unwind_v8(u32 rec_idx);
EBPF_GLOBAL int unwind_dotnet(u32 rec_idx);
EBPF_GLOBAL int unwind_dotnet10(u32 rec_idx);
EBPF_GLOBAL int unwind_beam(u32 rec_idx);
EBPF_GLOBAL int unwind_luajit(u32 rec_idx);

// unwind_stop finalizes the trace: correlation IDs, error frames and metrics.
// It returns a mask of UNWIND_STOP_* telling the entry program what still has to
// happen with the program context it holds and the unwinder does not.
EBPF_GLOBAL int unwind_stop(u32 rec_idx);

// go_labels extracts Go custom labels into the trace. Split out of unwind_stop
// because together they exceed the verifier's complexity limit.
EBPF_GLOBAL int go_labels(u32 rec_idx);

// trace_send hands the finished trace to userspace.
EBPF_GLOBAL int trace_send(u32 rec_idx);

// unwind_dispatch runs one unwinder and returns the next one to run.
//
// A switch rather than an indirect call: BPF has no function pointers, and the
// verifier needs to see every call target statically to check the stack depth of
// the whole chain.
//
// Every unwinder appears here whether or not its interpreter is enabled, unlike
// the program array this replaces, which only held the enabled ones. Disabling
// still works because nothing reaches an unwinder unless the loader has put an
// entry for it in interpreter_offsets or in a stack delta; the cost is that a
// disabled interpreter's unwinder is still verified at load time.
static inline EBPF_INLINE int unwind_dispatch(int unwinder, u32 rec_idx)
{
  // clang-format off
  switch (unwinder) {
  case PROG_UNWIND_NATIVE:   return unwind_native(rec_idx);
  case PROG_UNWIND_HOTSPOT:  return unwind_hotspot(rec_idx);
  case PROG_UNWIND_PERL:     return unwind_perl(rec_idx);
  case PROG_UNWIND_PYTHON:   return unwind_python(rec_idx);
  case PROG_UNWIND_PHP:      return unwind_php(rec_idx);
  case PROG_UNWIND_RUBY:     return unwind_ruby(rec_idx);
  case PROG_UNWIND_V8:       return unwind_v8(rec_idx);
  case PROG_UNWIND_DOTNET:   return unwind_dotnet(rec_idx);
  case PROG_UNWIND_DOTNET10: return unwind_dotnet10(rec_idx);
  case PROG_UNWIND_BEAM:     return unwind_beam(rec_idx);
  case PROG_UNWIND_LUAJIT:   return unwind_luajit(rec_idx);
  default:                   return PROG_UNWIND_STOP;
  }
  // clang-format on
}

// unwind_loop drives the unwinders for one trace and reports the result.
//
// ctx is only used for the PID notification, which needs a program context for
// bpf_perf_event_output; everything else is reached through the per-CPU record.
static inline EBPF_INLINE void unwind_loop(void *ctx, u32 rec_idx, int unwinder)
{
  u32 i;
  for (i = 0; i < MAX_UNWIND_ITERATIONS && unwinder != PROG_UNWIND_STOP; i++) {
    unwinder = unwind_dispatch(unwinder, rec_idx);
  }

  if (unwinder != PROG_UNWIND_STOP) {
    // Deep stacks and unwinder bugs both end up here. Report what was collected
    // so far with an error frame appended rather than dropping the trace.
    DEBUG_PRINT("unwind loop hit the iteration limit with unwinder %d pending", unwinder);
    PerCPURecord *record = get_per_cpu_record(rec_idx);
    if (record) {
      record->state.unwind_error = ERR_MAX_UNWIND_ITERATIONS;
    }
    increment_metric(metricID_MaxUnwindIterations);
  }

  int flags = unwind_stop(rec_idx);

  if (flags & UNWIND_STOP_REPORT_PID) {
    event_send_trigger(ctx, EVENT_TYPE_GENERIC_PID);
  }
  if (flags & UNWIND_STOP_DROP) {
    return;
  }
  if (flags & UNWIND_STOP_GO_LABELS) {
    go_labels(rec_idx);
  }
  trace_send(rec_idx);
}

#endif // OPTI_UNWINDERS_H
