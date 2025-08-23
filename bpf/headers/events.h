#ifndef __EVENTS_H__
#define __EVENTS_H__


#ifndef TASK_COMM_SIZE
#define TASK_COMM_SIZE 150
#endif

#define MOUNT_STR_SIZE 128

#ifndef PATH_MAX
#define PATH_MAX 256
#endif

#ifndef AF_INET
#define AF_INET  2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
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

struct socket_event_t{
  // Process and user info
    u32 pid;
    u32 uid;
    u32 gid;
    u64 cgroup_id;
    u32 ppid;
    u8 comm[TASK_COMM_SIZE];             
    u8 cgroup_name[TASK_COMM_SIZE];
    u32 user_pid;
    u32 user_ppid;

    // Timestamps
    u64 timestamp_ns_enter;
    u64 timestamp_ns_exit;
    u64 latency_ns;

    // Return value from syscall
    long ret;

    // Syscall-specific info
    u16 sa_family;
    u32 saddrV4;
    u32 daddrV4;
    __u8 saddrV6[16];
	  __u8 daddrV6[16];
    u16 sport;
    u16 dport;
};


struct ptrace_event_t{
    u32 pid;
    u32 uid;
    u32 gid;
    u64 cgroup_id;
    u32 ppid;
    u8 cgroup_name[TASK_COMM_SIZE];
    u32 user_pid;
    u32 user_ppid;
    u8 comm[TASK_COMM_SIZE];
    u64 timestamp_ns;
    long ret;
    u64 latency;
    u64 timestamp_ns_exit;
    // ptrace arguments
    long request;
    long pid_ptrace;
    unsigned long addr;
    unsigned long data;
};

struct mmap_event_t{
    u32 pid;
    u32 uid;
    u32 gid;
    u64 cgroup_id;
    u32 ppid;
    u8 cgroup_name[TASK_COMM_SIZE];
    u32 user_pid;
    u32 user_ppid;
    u8 comm[TASK_COMM_SIZE];
    u64 timestamp_ns;
    long ret;
    u64 latency;
    u64 timestamp_ns_exit;
    // mmap arguments
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    unsigned long fd;
    unsigned long off;
};

struct mount_event_t{
    u32 pid;
    u32 uid;
    u32 gid;
    u64 cgroup_id;
    u32 ppid;
    u8 cgroup_name[TASK_COMM_SIZE];
    u32 user_pid;
    u32 user_ppid;
    u8 comm[TASK_COMM_SIZE];
    u64 timestamp_ns;
    long ret;
    u64 latency;
    u64 timestamp_ns_exit;
    // mount arguments
    u8 dev_name[MOUNT_STR_SIZE];
    u8 dir_name[MOUNT_STR_SIZE];
    u8 type[MOUNT_STR_SIZE];
    unsigned long flags;
};

struct resource_event_t{
    u32 pid;
    u32 uid;
    u32 gid;
    u64 cgroup_id;
    u32 ppid;
    u8 cgroup_name[TASK_COMM_SIZE];
    u32 user_pid;
    u32 user_ppid;
    u8 comm[TASK_COMM_SIZE];
    u64 timestamp_ns;
    u64 latency;
    u64 timestamp_ns_exit;
    u64 cpu_ns;
    u64 user_faults;
    u64 kernel_faults;
    u64 vm_mmap_bytes;
    u64 vm_munmap_bytes;
    u64 vm_brk_grow_bytes;
    u64 vm_brk_shrink_bytes;
    u64 last_seen_ns;
};

#endif /* __EVENTS_H__ */

