//go:build ignore

#include "../headers/vmlinux.h"
#include "../headers/events.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct mmap_event_t);
} tmp_event_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events_mmap SEC(".maps");

struct{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, struct mmap_event_t);
  __uint(max_entries, 1024);
} start_events_mmap SEC(".maps");

const struct mmap_event_t *unused __attribute__((unused));

SEC("tracepoint/syscalls/sys_enter_mmap")
int handle_enter_mmap( struct trace_event_raw_sys_enter *ctx){
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 key = 0;

  struct mmap_event_t *event = bpf_map_lookup_elem(&tmp_event_map, &key);
  if (!event)
      return 0;

  // zero out memory (since it's reused)
  __builtin_memset(event, 0, sizeof(*event));

  event->pid = pid_tgid >> 32;
  u64 uid_gid = bpf_get_current_uid_gid();
  event->uid = uid_gid >> 32;
  event->gid = uid_gid & 0xFFFFFFFF;
  event->cgroup_id = bpf_get_current_cgroup_id();

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  event->ppid = BPF_CORE_READ(task, real_parent, tgid);

  const char *cname = BPF_CORE_READ(task, cgroups, subsys[ memory_cgrp_id], cgroup, kn, name);
  bpf_core_read_str(event->cgroup_name, sizeof(event->cgroup_name), cname);

  struct task_struct *parent_task = BPF_CORE_READ(task, real_parent);
  struct nsproxy *namespaceproxy = BPF_CORE_READ(task, nsproxy);
  struct pid_namespace *pid_ns_children = BPF_CORE_READ(namespaceproxy, pid_ns_for_children);
  unsigned int level = BPF_CORE_READ(pid_ns_children, level);
  event->user_pid = BPF_CORE_READ(task, group_leader, thread_pid, numbers[level].nr);

  struct nsproxy *parent_namespaceproxy = BPF_CORE_READ(parent_task, nsproxy);
  struct pid_namespace *parent_pid_ns_children = BPF_CORE_READ(parent_namespaceproxy, pid_ns_for_children);
  unsigned int parent_level = BPF_CORE_READ(parent_pid_ns_children, level);
  event->user_ppid = BPF_CORE_READ(parent_task, group_leader, thread_pid, numbers[parent_level].nr);

  bpf_get_current_comm(&event->comm, TASK_COMM_SIZE);
  event->addr = (long) ctx->args[0];
  event->len = (long) ctx->args[1];
  event->prot = (long) ctx->args[2];
  event->flags = (long) ctx->args[3];
  event->fd = (long) ctx->args[4];
  event->off = (long) ctx->args[5];

  event->timestamp_ns = bpf_ktime_get_ns();

  bpf_map_update_elem(&start_events_mmap, &pid_tgid, event, BPF_ANY);
  return 0;

}

SEC("tracepoint/syscalls/sys_exit_mmap")
int handle_exit_mmap(struct trace_event_raw_sys_exit *ctx){
  
  struct mmap_event_t *event;

  u64 pid_tgid = bpf_get_current_pid_tgid();

  event = bpf_map_lookup_elem(&start_events_mmap,&pid_tgid);
  if (!event)
    return 0;

  struct mmap_event_t *final_event;

  final_event = bpf_ringbuf_reserve(&events_mmap,sizeof(struct mmap_event_t),0);

  if(!final_event) return 0;

  long ret = ctx->ret;

  __builtin_memcpy(final_event, event, sizeof(struct mmap_event_t));

  final_event->ret = ret;
  u64 now = bpf_ktime_get_ns();
  final_event->timestamp_ns_exit = now;
  final_event->latency = now - event->timestamp_ns;


  bpf_ringbuf_submit(final_event,0);

  bpf_map_delete_elem(&start_events_mmap,&pid_tgid);

  return 0;

}
