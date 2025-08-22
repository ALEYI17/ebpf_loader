//go:build ignore

#include "../headers/vmlinux.h"
#include "../headers/events.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} run_start_ns SEC(".maps");

struct{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(value,struct resource_event_t);
  __type(key, __u32);
} resource_table SEC(".maps");

const struct resource_event_t *unused __attribute__((unused));

static __always_inline u32 task_tgid(struct task_struct *t)
{
    u32 tgid = 0;
    bpf_core_read(&tgid, sizeof(tgid), &t->tgid);
    if (!tgid) {
        struct task_struct *gl = BPF_CORE_READ(t, group_leader);
        if (gl)
            tgid = BPF_CORE_READ(gl, tgid);
    }
    return tgid;
}

SEC("kprobe/finish_task_switch")
int BPF_KPROBE(handle_finish_task_switch, struct task_struct *prev){

  u64 now = bpf_ktime_get_ns();

  if (prev){
    u32 prev_pid = task_tgid(prev);

    if (prev_pid > 0 ){
      struct resource_event_t *eventp;

      eventp = bpf_map_lookup_elem(&resource_table,&prev_pid);
      if(!eventp){
        struct resource_event_t new_event= {};

        new_event.pid = prev_pid;
        bpf_core_read_str(new_event.comm, sizeof(new_event.comm), &prev->comm);
        bpf_map_update_elem(&resource_table, &prev_pid, &new_event, BPF_ANY);
        eventp = bpf_map_lookup_elem(&resource_table, &prev_pid);
      }

      if (eventp){
        eventp->timestamp_ns = now;
        eventp->last_seen_ns = now;

        u64 *startp = bpf_map_lookup_elem(&run_start_ns, &prev_pid);
        if(startp){
          u64 delta = now - *startp;
          eventp->cpu_ns += delta;
          bpf_map_delete_elem(&run_start_ns, &prev_pid);
        }
      }
      
    }
  }

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 cur_pid = pid_tgid >> 32;

  if (cur_pid > 0) {
        bpf_map_update_elem(&run_start_ns, &cur_pid, &now, BPF_ANY);
  }

  return 0;
}

SEC("tracepoint/exceptions/page_fault_user")
int handle_page_fault_user( struct trace_event_raw_sys_enter *ctx){

  u32 pid = bpf_get_current_pid_tgid() >> 32;

  struct resource_event_t *eventp;

  if (pid == 0)
    return 0;

  eventp = bpf_map_lookup_elem(&resource_table, &pid);

  if(!eventp){
    struct resource_event_t new_event = {};
    new_event.pid = pid;
    bpf_get_current_comm(&new_event.comm, sizeof(new_event.comm));
    bpf_map_update_elem(&resource_table, &pid, &new_event, BPF_ANY);
    eventp = bpf_map_lookup_elem(&resource_table, &pid);
  }

  if (eventp){
    __sync_fetch_and_add(&eventp->user_faults, 1);
    eventp->last_seen_ns = bpf_ktime_get_ns();
  }
  return 0;
}

SEC("tracepoint/exceptions/page_fault_kernel")
int handle_page_fault_kernel( struct trace_event_raw_sys_enter *ctx){

  u32 pid = bpf_get_current_pid_tgid() >> 32;

  struct resource_event_t *eventp;

  if (pid == 0)
    return 0;

  eventp = bpf_map_lookup_elem(&resource_table, &pid);

  if(!eventp){
    struct resource_event_t new_event = {};
    new_event.pid = pid;
    bpf_get_current_comm(&new_event.comm, sizeof(new_event.comm));
    bpf_map_update_elem(&resource_table, &pid, &new_event, BPF_ANY);
    eventp = bpf_map_lookup_elem(&resource_table, &pid);
  }

  if (eventp){
    __sync_fetch_and_add(&eventp->kernel_faults, 1);
    eventp->last_seen_ns = bpf_ktime_get_ns();
  }
  return 0;
}
