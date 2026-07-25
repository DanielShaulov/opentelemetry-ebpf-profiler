#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"
#include "unwinders.h"

// origin_id_probe is set during load time.
BPF_RODATA_VAR(u16, origin_id_probe, 0)

// kprobe__generic serves as entry point for kprobe and uprobe based profiling.
SEC("kprobe/generic")
int kprobe__generic(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();

  // uprobes are not covered by bpf_prog_active, so a perf sample can interrupt
  // an unwind in progress here. Use the record reserved for probes so the two
  // cannot share half-built traces.
  int unwinder = collect_trace(ctx, PER_CPU_RECORD_PROBE, origin_id_probe, pid, tid, ts, 0);
  if (unwinder != PROG_UNWIND_NO_TRACE) {
    unwind_loop(ctx, PER_CPU_RECORD_PROBE, unwinder);
  }
  return 0;
}
