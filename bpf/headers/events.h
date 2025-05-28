#ifndef __EVENTS_H__
#define __EVENTS_H__


#ifndef TASK_COMM_SIZE
#define TASK_COMM_SIZE 150
#endif

#ifndef PATH_MAX
#define PATH_MAX 256
#endif

#ifndef AF_INET
#define AF_INET  2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif



struct trace_syscall_event {
    u32 pid;
    u32 uid;
    u32 gid;
    u64 cgroup_id;
    u32 ppid;
    u8 cgroup_name[TASK_COMM_SIZE];
    u32 user_pid;
    u32 user_ppid;
    u8 comm[TASK_COMM_SIZE];
    u8 filename[PATH_MAX];
    u64 timestamp_ns;
    long ret;
    u64 latency;
    u64 timestamp_ns_exit;
};

#endif /* __EVENTS_H__ */

