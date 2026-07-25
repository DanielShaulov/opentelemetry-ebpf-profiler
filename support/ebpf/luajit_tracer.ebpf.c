// This file contains the code and map definitions for the LuaJIT tracer

#include "bpfdefs.h"
#include "errors.h"
#include "tracemgmt.h"
#include "types.h"

struct luajit_procs_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, pid_t);
  __type(value, LuaJITProcInfo);
  __uint(max_entries, 1024);
} luajit_procs SEC(".maps");

// Unimplemented; just a stub that compiles and references the map.
EBPF_GLOBAL int unwind_luajit(u32 rec_idx)
{
  PerCPURecord *record = get_per_cpu_record(rec_idx);
  if (!record)
    return PROG_UNWIND_STOP;

  u32 pid              = record->trace.pid;
  ErrorCode error      = ERR_UNREACHABLE; // We never run this unwinder.
  LuaJITProcInfo *info = bpf_map_lookup_elem(&luajit_procs, &pid);
  if (!info) {
    DEBUG_PRINT("lj: no LuaJIT introspection data");
    error = ERR_LUAJIT_NO_PROC_INFO;
    increment_metric(metricID_UnwindLuaJITErrNoProcInfo);
    goto exit;
  }
  increment_metric(metricID_UnwindLuaJITAttempts);

exit:
  record->state.unwind_error = error;
  return PROG_UNWIND_STOP;
}
