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

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

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
      struct resource_event_t event = {};
      
      event.pid = prev_pid;
      bpf_core_read_str(event.comm, sizeof(event.comm), &prev->comm);
      // u64 uid_gid = bpf_get_current_uid_gid();
      //event.uid = uid_gid >> 32;
      //event.gid = uid_gid & 0xFFFFFFFF;
      //event.cgroup_id = bpf_get_current_cgroup_id();

      /*struct task_struct *task = (struct task_struct *)bpf_get_current_task();*/
      /*event.ppid = BPF_CORE_READ(task, real_parent, tgid);*/
      /**/
      /*const char *cname = BPF_CORE_READ(task, cgroups, subsys[ memory_cgrp_id], cgroup, kn, name);*/
      /*bpf_core_read_str(event.cgroup_name, sizeof(event.cgroup_name), cname);*/
      /**/
      /*struct task_struct *parent_task = BPF_CORE_READ(task, real_parent);*/
      /*struct nsproxy *namespaceproxy = BPF_CORE_READ(task, nsproxy);*/
      /*struct pid_namespace *pid_ns_children = BPF_CORE_READ(namespaceproxy, pid_ns_for_children);*/
      /*unsigned int level = BPF_CORE_READ(pid_ns_children, level);*/
      /*event.user_pid = BPF_CORE_READ(task, group_leader, thread_pid, numbers[level].nr);*/
      /**/
      /*struct nsproxy *parent_namespaceproxy = BPF_CORE_READ(parent_task, nsproxy);*/
      /*struct pid_namespace *parent_pid_ns_children = BPF_CORE_READ(parent_namespaceproxy, pid_ns_for_children);*/
      /*unsigned int parent_level = BPF_CORE_READ(parent_pid_ns_children, level);*/
      /*event.user_ppid = BPF_CORE_READ(parent_task, group_leader, thread_pid, numbers[parent_level].nr);*/
      /**/
      /*bpf_get_current_comm(&event.comm, TASK_COMM_SIZE);*/

      event.timestamp_ns = now;
      u64 *startp = bpf_map_lookup_elem(&run_start_ns, &prev_pid);
      if (startp) {
          u64 delta = now - *startp;
          event.cpu_ns = delta;
          bpf_map_delete_elem(&run_start_ns, &prev_pid);
      }

/*      struct mm_struct *mm = BPF_CORE_READ(prev, mm);*/
/**/
/*      if(mm){*/
/*        long file = 0, anon = 0;*/
/*#ifdef MM_FILEPAGES*/
/*        file = BPF_CORE_READ(mm, rss_stat.count[MM_FILEPAGES].counter);*/
/*        anon = BPF_CORE_READ(mm, rss_stat.count[MM_ANONPAGES].counter);*/
/*#else */
/*        file = BPF_CORE_READ(mm, rss_stat.count[1].counter);*/
/*        anon = BPF_CORE_READ(mm, rss_stat.count[0].counter);*/
/*#endif*/
/*        event.rss_bytes = ((u64)(file + anon)) << PAGE_SHIFT;*/
/*      }*/
      event.last_seen_ns = now;

      
      bpf_perf_event_output(ctx,&events,BPF_F_CURRENT_CPU,&event,sizeof(event));
    }
  }

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 cur_pid = pid_tgid >> 32;

  if (cur_pid > 0) {
        bpf_map_update_elem(&run_start_ns, &cur_pid, &now, BPF_ANY);
  }

  return 0;
}

