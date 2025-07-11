//go:build ignore
#include "../headers/vmlinux.h"
#include "../headers/events.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} connect_events SEC(".maps");

struct{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, struct sock *);
  __uint(max_entries, 1024);
} connect_start_events SEC(".maps");

struct{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, u64);
  __uint(max_entries, 1024);
} connect_events_ts SEC(".maps");

const struct socket_event_t *unused __attribute__((unused));

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(handle_tcp_v4_connect , struct sock *sk ){
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u64 ts = bpf_ktime_get_ns();
  bpf_map_update_elem(&connect_start_events,&pid_tgid,&sk,BPF_ANY);
  bpf_map_update_elem(&connect_events_ts,&pid_tgid,&ts,BPF_ANY);
  return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(handle_tcp_v4_connect_ret, int ret){
  struct sock **skpp; 
  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct sock *sk;
  skpp = bpf_map_lookup_elem(&connect_start_events,&pid_tgid);
  
  if (!skpp)
    return 0;
  
  u64 *ts_enter = bpf_map_lookup_elem(&connect_events_ts,&pid_tgid);
  if (!ts_enter) return 0;
  sk = *skpp;

  struct socket_event_t *event;

  event = bpf_ringbuf_reserve(&connect_events,sizeof(struct socket_event_t),0);
  if (!event){
    bpf_map_delete_elem(&connect_start_events,&pid_tgid);
    bpf_map_delete_elem(&connect_events_ts,&pid_tgid);
    return 0;
  }
  
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
  
  if (ret == 0 && sk ){
    u16 sa_family = BPF_CORE_READ(sk,__sk_common.skc_family );
  
    event->sa_family = sa_family;

    if (sa_family == AF_INET){
      event->saddrV4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
      event->daddrV4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
      event->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
      event->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport)); 
      __builtin_memset(event->saddrV6, 0, sizeof(event->saddrV6));
      __builtin_memset(event->daddrV6, 0, sizeof(event->daddrV6));
    }
    else{
      event->saddrV4 = 0;
      event->daddrV4 = 0;
      event->sport = 0;
      event->dport = 0;
      __builtin_memset(event->saddrV6, 0, sizeof(event->saddrV6));
      __builtin_memset(event->daddrV6, 0, sizeof(event->daddrV6));
    }

  }
  else {
    event->sa_family = 0;
    event->saddrV4 = 0;
    event->daddrV4 = 0;
    event->sport = 0;
    event->dport = 0;
    __builtin_memset(event->saddrV6, 0, sizeof(event->saddrV6));
    __builtin_memset(event->daddrV6, 0, sizeof(event->daddrV6));
  }
  
  event->ret = ret;
  event->timestamp_ns_enter = *ts_enter;
  event->timestamp_ns_exit = bpf_ktime_get_ns();
  event->latency_ns = event->timestamp_ns_exit - event->timestamp_ns_enter;

  bpf_map_delete_elem(&connect_events_ts,&pid_tgid);
  bpf_map_delete_elem(&connect_start_events,&pid_tgid);
  bpf_ringbuf_submit(event,0);
  return 0;
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(handle_tcp_v6_connect , struct sock *sk ){
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u64 ts = bpf_ktime_get_ns();
  bpf_map_update_elem(&connect_start_events,&pid_tgid,&sk,BPF_ANY);
  bpf_map_update_elem(&connect_events_ts,&pid_tgid,&ts,BPF_ANY);
  return 0;
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(handle_tcp_v6_connect_ret, int ret){
  struct sock **skpp; 
  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct sock *sk;
  skpp = bpf_map_lookup_elem(&connect_start_events,&pid_tgid);
  
  if (!skpp)
    return 0;
  
  u64 *ts_enter = bpf_map_lookup_elem(&connect_events_ts,&pid_tgid);
  if (!ts_enter) return 0;
  sk = *skpp;

  struct socket_event_t *event;

  event = bpf_ringbuf_reserve(&connect_events,sizeof(struct socket_event_t),0);
  if (!event){
    bpf_map_delete_elem(&connect_events_ts,&pid_tgid);
    bpf_map_delete_elem(&connect_start_events,&pid_tgid);
    return 0;
  }
  
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
  
  if (ret == 0 && sk ){
    u16 sa_family = BPF_CORE_READ(sk,__sk_common.skc_family );
  
    event->sa_family = sa_family;

    if (sa_family == AF_INET6){
      event->saddrV4 = 0;
      event->daddrV4 = 0;
      event->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
      event->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport)); 
      BPF_CORE_READ_INTO(&event->saddrV6,sk,__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
      BPF_CORE_READ_INTO(&event->daddrV6,sk,__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }
    else{
      event->saddrV4 = 0;
      event->daddrV4 = 0;
      event->sport = 0;
      event->dport = 0;
      __builtin_memset(event->saddrV6, 0, sizeof(event->saddrV6));
      __builtin_memset(event->daddrV6, 0, sizeof(event->daddrV6));
    }

  }
  else {
    event->sa_family = 0;
    event->saddrV4 = 0;
    event->daddrV4 = 0;
    event->sport = 0;
    event->dport = 0;
    __builtin_memset(event->saddrV6, 0, sizeof(event->saddrV6));
    __builtin_memset(event->daddrV6, 0, sizeof(event->daddrV6));
  }
  
  event->ret = ret;
  event->timestamp_ns_enter = *ts_enter;
  event->timestamp_ns_exit = bpf_ktime_get_ns();
  event->latency_ns = event->timestamp_ns_exit - event->timestamp_ns_enter;

  bpf_map_delete_elem(&connect_events_ts,&pid_tgid);
  bpf_map_delete_elem(&connect_start_events,&pid_tgid);
  bpf_ringbuf_submit(event,0);
  return 0;
}

