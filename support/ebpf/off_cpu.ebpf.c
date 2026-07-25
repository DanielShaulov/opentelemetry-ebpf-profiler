#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"
#include "unwinders.h"

// sched_times keeps track of sched_switch call times.
struct sched_times_t {
  __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
  __type(key, u64);         // pid_tgid
  __type(value, u64);       // time in ns
  __uint(max_entries, 256); // value is adjusted at load time in loadAllMaps.
} sched_times SEC(".maps");

// off_cpu_threshold is set during load time.
BPF_RODATA_VAR(u32, off_cpu_threshold, 0)

// origin_id_off_cpu is set during load time.
BPF_RODATA_VAR(u16, origin_id_off_cpu, 0)

// tracepoint__sched_switch serves as entry point for off cpu profiling.
SEC("tracepoint/sched/sched_switch")
int tracepoint__sched_switch(UNUSED void *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0) {
    return 0;
  }

  if (bpf_get_prandom_u32() > off_cpu_threshold) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();

  if (bpf_map_update_elem(&sched_times, &pid_tgid, &ts, BPF_ANY) < 0) {
    DEBUG_PRINT("Failed to record sched_switch event entry");
    return 0;
  }

  return 0;
}

// kp__finish_task_switch is triggered right after the scheduler updated
// the CPU registers.
SEC("kprobe/finish_task_switch")
int finish_task_switch(struct pt_regs *ctx)
{
  // Get the PID and TGID register.
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();

  u64 *start_ts = bpf_map_lookup_elem(&sched_times, &pid_tgid);
  if (!start_ts || *start_ts == 0) {
    // There is no information from the sched/sched_switch entry hook.
    return 0;
  }

  // Remove entry from the map so the stack for the same pid_tgid does not get unwound and
  // reported accidentally without the start timestamp updated in tracepoint/sched/sched_switch.
  bpf_map_delete_elem(&sched_times, &pid_tgid);

  // diff stores the nanoseconds that the trace was off-cpu for.
  u64 diff = ts - *start_ts;
  DEBUG_PRINT("==== finish_task_switch ====");

  // Off-CPU unwinding runs from a kprobe, which bpf_prog_active does not protect
  // against a perf sample landing on top of it, so it uses the probe record.
  int unwinder = collect_trace(ctx, PER_CPU_RECORD_PROBE, origin_id_off_cpu, pid, tid, ts, diff);
  if (unwinder != PROG_UNWIND_NO_TRACE) {
    unwind_loop(ctx, PER_CPU_RECORD_PROBE, unwinder);
  }
  return 0;
}
