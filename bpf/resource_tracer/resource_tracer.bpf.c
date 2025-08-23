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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);   // pid
    __type(value, __u64); // len
} pending_mmap_len SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} pending_munmap_len SEC(".maps");


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

static __always_inline struct resource_event_t *get_or_init_event(__u32 pid){
    struct resource_event_t *e = bpf_map_lookup_elem(&resource_table, &pid);
    if (!e) {
        struct resource_event_t ne = {};
        ne.pid = pid;
        bpf_get_current_comm(ne.comm, sizeof(ne.comm));
        bpf_map_update_elem(&resource_table, &pid, &ne, BPF_ANY);
        e = bpf_map_lookup_elem(&resource_table, &pid);
    }
    return e;
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

SEC("tracepoint/syscall/sys_enter_mmap")
int tp_enter_mmap(struct trace_event_raw_sys_enter *ctx){
  
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  long len = (long) ctx->args[1];
  bpf_map_update_elem(&pending_mmap_len, &pid, &len, BPF_ANY);
  return 0;
}

SEC("tracepoint/syscall/sys_enter_mmap")
int tp_exit_mmap(struct trace_event_raw_sys_exit *ctx){

  u32 pid = bpf_get_current_pid_tgid() >>32;
  long ret = (long) ctx->ret; 
  long *lenp = bpf_map_lookup_elem(&pending_mmap_len,&pid);

  if(!lenp) return 0;

  if (ret >= 0){
    struct resource_event_t *e = get_or_init_event(pid);

    if (e){
      __sync_fetch_and_add(&e->vm_mmap_bytes, *lenp);
      e->last_seen_ns = bpf_ktime_get_ns();
    }
  }

  bpf_map_delete_elem(&pending_mmap_len, &pid);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_munmap")
int tp_enter_munmap(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 len = (u64)ctx->args[1];
    bpf_map_update_elem(&pending_munmap_len, &pid, &len, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_munmap")
int tp_exit_munmap(struct trace_event_raw_sys_exit *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __s64 ret = ctx->ret;
    __u64 *lenp = bpf_map_lookup_elem(&pending_munmap_len, &pid);
    if (!lenp) return 0;

    if (ret == 0) {
        struct resource_event_t *e = get_or_init_event(pid);
        if (e) {
            __sync_fetch_and_add(&e->vm_munmap_bytes, *lenp);
            e->last_seen_ns = bpf_ktime_get_ns();
        }
    }
    bpf_map_delete_elem(&pending_munmap_len, &pid);
    return 0;
}
