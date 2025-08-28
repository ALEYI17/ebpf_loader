//go:build ignore

#include "../headers/vmlinux.h"
#include "../headers/events.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct syscall_key);
    __type(value, __u64);
} syscount_map SEC(".maps");

const struct syscall_key *unused __attribute__((unused));


SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx){

  struct syscall_key key = {};
  __u64 one = 1;
  __u64 *val;

  key.syscall_nr = ( __u32 ) ctx->id;
  key.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);

  val = bpf_map_lookup_elem(&syscount_map, &key);
  if (val){
    __sync_fetch_and_add(val, 1);
  }else{
    bpf_map_update_elem(&syscount_map, &key, &one, BPF_ANY);
  }

  return 0;
}
