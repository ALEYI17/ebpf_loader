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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);    
    __type(value, struct process_metadata_t);
    __uint(max_entries, 16384);
} meta_cache SEC(".maps");

const struct syscall_key *unused __attribute__((unused));
const struct process_metadata_t *unused2 __attribute__((unused));


static __always_inline struct process_metadata_t *get_or_init_event(__u32 pid){
    struct process_metadata_t *e = bpf_map_lookup_elem(&meta_cache, &pid);
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

        bpf_map_update_elem(&meta_cache, &pid, &ne, BPF_ANY);
        e = bpf_map_lookup_elem(&meta_cache, &pid);
    }
    return e;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx){

  struct syscall_key key = {};
  __u64 one = 1;
  __u64 *val;

  key.syscall_nr = ( __u32 ) ctx->id;
  key.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);

  get_or_init_event(key.pid);

  val = bpf_map_lookup_elem(&syscount_map, &key);
  if (val){
    __sync_fetch_and_add(val, 1);
  }else{
    bpf_map_update_elem(&syscount_map, &key, &one, BPF_ANY);
  }

  return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_sched_process_exit(struct trace_event_raw_sched_process_template *ctx){
  u32 pid = bpf_get_current_pid_tgid() >> 32; 
  bpf_map_delete_elem(&meta_cache, &pid);
  return 0;
}

