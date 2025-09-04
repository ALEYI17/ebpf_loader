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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64); 
} last_brk_end SEC(".maps");

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

        u64 uid_gid = bpf_get_current_uid_gid();
        ne.uid = uid_gid >> 32;
        ne.gid = uid_gid & 0xFFFFFFFF;
        ne.cgroup_id = bpf_get_current_cgroup_id();
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        ne.ppid = BPF_CORE_READ(task, real_parent, tgid);
        const char *cname = BPF_CORE_READ(task, cgroups, subsys[ memory_cgrp_id], cgroup, kn, name);
        bpf_core_read_str(ne.cgroup_name, sizeof(ne.cgroup_name), cname);

        struct task_struct *parent_task = BPF_CORE_READ(task, real_parent);
        struct nsproxy *namespaceproxy = BPF_CORE_READ(task, nsproxy);
        struct pid_namespace *pid_ns_children = BPF_CORE_READ(namespaceproxy, pid_ns_for_children);
        unsigned int level = BPF_CORE_READ(pid_ns_children, level);
        ne.user_pid = BPF_CORE_READ(task, group_leader, thread_pid, numbers[level].nr);

        struct nsproxy *parent_namespaceproxy = BPF_CORE_READ(parent_task, nsproxy);
        struct pid_namespace *parent_pid_ns_children = BPF_CORE_READ(parent_namespaceproxy, pid_ns_for_children);
        unsigned int parent_level = BPF_CORE_READ(parent_pid_ns_children, level);
        ne.user_ppid = BPF_CORE_READ(parent_task, group_leader, thread_pid, numbers[parent_level].nr);


        bpf_get_current_comm(ne.comm, sizeof(ne.comm));

        bpf_map_update_elem(&resource_table, &pid, &ne, BPF_ANY);
        e = bpf_map_lookup_elem(&resource_table, &pid);
    }
    return e;
}

static __always_inline struct resource_event_t *get_or_init_event_switch(__u32 pid, struct task_struct *p){
    struct resource_event_t *e = bpf_map_lookup_elem(&resource_table, &pid);
    if (!e) {
        struct resource_event_t ne = {};
        ne.pid = pid;
        BPF_CORE_READ_STR_INTO(&ne.comm, p, comm);

        ne.uid = BPF_CORE_READ(p, real_cred, uid.val);
        ne.gid = BPF_CORE_READ(p, real_cred, gid.val);
        
        ne.ppid = BPF_CORE_READ(p, real_parent, tgid);
        
        ne.cgroup_id = BPF_CORE_READ(p, cgroups, dfl_cgrp, kn, id);
        const char *cname = BPF_CORE_READ(p, cgroups, dfl_cgrp, kn, name);
        bpf_core_read_str(ne.cgroup_name, sizeof(ne.cgroup_name), cname);

        struct task_struct *parent_task = BPF_CORE_READ(p, real_parent);
        struct nsproxy *namespaceproxy = BPF_CORE_READ(p, nsproxy);
        struct pid_namespace *pid_ns_children = BPF_CORE_READ(namespaceproxy, pid_ns_for_children);
        unsigned int level = BPF_CORE_READ(pid_ns_children, level);
        ne.user_pid = BPF_CORE_READ(p, group_leader, thread_pid, numbers[level].nr);


        bpf_map_update_elem(&resource_table, &pid, &ne, BPF_ANY);
        e = bpf_map_lookup_elem(&resource_table, &pid);
    }
    return e;
}


SEC("kprobe/finish_task_switch")
int BPF_KPROBE(handle_finish_task_switch, struct task_struct *prev){

  u64 now = bpf_ktime_get_ns();

  if (prev){
    if (BPF_CORE_READ(prev, mm)){
    u32 prev_pid = task_tgid(prev);

      if (prev_pid > 0 ){
        struct resource_event_t *eventp;

        eventp = get_or_init_event_switch(prev_pid,prev);
        if(!eventp){
          struct resource_event_t new_event= {};

          new_event.pid = prev_pid;
          bpf_core_read_str(new_event.comm, sizeof(new_event.comm), &prev->comm);
          bpf_map_update_elem(&resource_table, &prev_pid, &new_event, BPF_ANY);
          eventp = bpf_map_lookup_elem(&resource_table, &prev_pid);
        }
        
        if (eventp){
          eventp->last_seen_ns = now;

          u64 *startp = bpf_map_lookup_elem(&run_start_ns, &prev_pid);
          if(startp){
            u64 delta = now - *startp;
             __sync_fetch_and_add(&eventp->cpu_ns, delta);
            bpf_map_delete_elem(&run_start_ns, &prev_pid);
          }
        }
        
      }

    }
  }

  struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
  if (curr && BPF_CORE_READ(curr, mm)){
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 cur_pid = pid_tgid >> 32;

    if (cur_pid > 0) {
      bpf_map_update_elem(&run_start_ns, &cur_pid, &now, BPF_ANY);
    }

  }
  
  return 0;
}

SEC("tracepoint/exceptions/page_fault_user")
int handle_page_fault_user( struct trace_event_raw_sys_enter *ctx){

  u32 pid = bpf_get_current_pid_tgid() >> 32;

  struct resource_event_t *eventp;

  if (pid == 0)
    return 0;

  eventp = get_or_init_event(pid);
  
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

  eventp = get_or_init_event(pid);

  if (eventp){
    __sync_fetch_and_add(&eventp->kernel_faults, 1);
    eventp->last_seen_ns = bpf_ktime_get_ns();
  }
  return 0;
}

SEC("tracepoint/syscall/sys_enter_mmap")
int tp_enter_mmap(struct trace_event_raw_sys_enter *ctx){
  
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u64 len = (u64) ctx->args[1];
  bpf_map_update_elem(&pending_mmap_len, &pid, &len, BPF_ANY);
  return 0;
}

SEC("tracepoint/syscall/sys_exit_mmap")
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
    long ret = (long) ctx->ret;
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

SEC("tracepoint/syscalls/sys_exit_brk")
int tp_exit_brk(struct trace_event_raw_sys_exit *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 new_brk = (__u64)ctx->ret;

    __u64 *prevp = bpf_map_lookup_elem(&last_brk_end, &pid);
    if (!prevp) {
        // initialize baseline
        bpf_map_update_elem(&last_brk_end, &pid, &new_brk, BPF_ANY);
        return 0;
    }

    if (new_brk != *prevp) {
        struct resource_event_t *e = get_or_init_event(pid);
        if (e) {
            if (new_brk > *prevp) {
                __sync_fetch_and_add(&e->vm_brk_grow_bytes, new_brk - *prevp);
            } else {
                __sync_fetch_and_add(&e->vm_brk_shrink_bytes, *prevp - new_brk);
            }
            e->last_seen_ns = bpf_ktime_get_ns();
        }
        bpf_map_update_elem(&last_brk_end, &pid, &new_brk, BPF_ANY);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_exit_read(struct trace_event_raw_sys_exit *ctx) {
    int ret = ctx->ret;
    if (ret > 0) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        struct resource_event_t *eventp = get_or_init_event(pid);
        if (eventp) {
            __sync_fetch_and_add(&eventp->bytes_read, ret);
        }
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int trace_exit_write(struct trace_event_raw_sys_exit *ctx) {
    int ret = ctx->ret;
    if (ret > 0) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        struct resource_event_t *eventp = get_or_init_event(pid);
        if (eventp) {
            __sync_fetch_and_add(&eventp->bytes_written, ret);
        }
    }
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_sched_process_exit(struct trace_event_raw_sched_process_template *ctx){
  u32 pid = bpf_get_current_pid_tgid() >> 32; 
  bpf_map_delete_elem(&resource_table, &pid);
  return 0;
}

