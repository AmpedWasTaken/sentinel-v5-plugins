// Sentinel native sandbox proof of concept. Linux x86_64 only.
// No setuid, no ambient root, no Docker. Build as ordinary non-setuid binary.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef __x86_64__
#error "Native sandbox seccomp architecture policy is x86_64-only"
#endif

#define FAIL(msg) do { perror(msg); _exit(125); } while (0)
#define DENY(nr) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, (nr), 0, 1), \
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|(EPERM & SECCOMP_RET_DATA))

static void write_file(const char *path, const char *value) {
    int fd = open(path, O_WRONLY|O_CLOEXEC);
    if (fd < 0) FAIL("open namespace map");
    size_t len = strlen(value);
    if (write(fd, value, len) != (ssize_t)len) FAIL("write namespace map");
    if (close(fd) != 0) FAIL("close namespace map");
}

static void set_limit(int resource, rlim_t value) {
    struct rlimit lim = {.rlim_cur=value, .rlim_max=value};
    if (setrlimit(resource, &lim) != 0) FAIL("setrlimit");
}

static int cap_last_cap(void) {
    int fd = open("/proc/sys/kernel/cap_last_cap", O_RDONLY|O_CLOEXEC);
    if (fd < 0) FAIL("read cap_last_cap");
    char buf[32] = {0};
    ssize_t count = read(fd, buf, sizeof(buf)-1);
    if (close(fd) != 0 || count < 1) FAIL("read cap_last_cap value");
    int highest = atoi(buf);
    if (highest < 0 || highest > 256) { errno=EINVAL; FAIL("invalid cap_last_cap"); }
    return highest;
}
static void drop_capabilities(int highest) {
    for (int i = 0; i <= highest; i++) {
        if (prctl(PR_CAPBSET_DROP, i, 0, 0, 0) != 0) FAIL("drop cap bounding set");
    }
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct data[2] = {{0},{0}};
    if (syscall(SYS_capset, &header, data) != 0) FAIL("clear capabilities");
}

static void install_seccomp(void) {
    // Defense in depth only. This denylist is NOT a comprehensive sandbox policy.
    // Fail closed if filter or architecture checks cannot be installed.
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, 0x40000000, 0, 1),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
        // Prevent creation of further namespaces via clone flags.
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_clone, 0, 4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,
            CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWNET|CLONE_NEWIPC|CLONE_NEWUTS|CLONE_NEWCGROUP,
            0, 1),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|(EPERM & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)),
        DENY(__NR_clone3),
        DENY(__NR_unshare),
        DENY(__NR_setns),
        DENY(__NR_mount),
        DENY(__NR_umount2),
        DENY(__NR_pivot_root),
        DENY(__NR_chroot),
        DENY(__NR_ptrace),
        DENY(__NR_bpf),
        DENY(__NR_perf_event_open),
        DENY(__NR_userfaultfd),
        DENY(__NR_keyctl),
        DENY(__NR_add_key),
        DENY(__NR_request_key),
        DENY(__NR_reboot),
        DENY(__NR_kexec_load),
        DENY(__NR_finit_module),
        DENY(__NR_init_module),
        DENY(__NR_delete_module),
        DENY(__NR_open_by_handle_at),
        DENY(__NR_io_uring_setup),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {.len=(unsigned short)(sizeof(filter)/sizeof(filter[0])), .filter=filter};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) FAIL("no_new_privs");
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) FAIL("seccomp filter");
}

static void enter_guest(const char *rootfs, unsigned long tmp_mib, unsigned long wall_sec,
                        char *const argv[], int highest_cap) {
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0) FAIL("parent death signal");
    if (mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL) != 0) FAIL("private mount tree");
    if (mount(rootfs, rootfs, NULL, MS_BIND, NULL) != 0) FAIL("rootfs bind");
    if (mount(NULL, rootfs, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV, NULL) != 0)
        FAIL("rootfs readonly remount");
    if (chdir(rootfs) != 0) FAIL("chdir rootfs");
    if (syscall(SYS_pivot_root, ".", ".") != 0) FAIL("pivot_root");
    if (umount2(".", MNT_DETACH) != 0) FAIL("detach old root");
    if (chdir("/") != 0) FAIL("chdir guest root");

    struct stat tmp;
    if (lstat("/tmp", &tmp) != 0 || !S_ISDIR(tmp.st_mode)) { errno=ENOENT; FAIL("guest /tmp directory required"); }
    char opts[96];
    if (snprintf(opts, sizeof(opts), "size=%lum,mode=1777", tmp_mib) >= (int)sizeof(opts)) _exit(125);
    if (mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID|MS_NODEV|MS_NOEXEC, opts) != 0) FAIL("guest tmpfs");
    if (sethostname("sentinel-sandbox", 16) != 0) FAIL("guest hostname");
    set_limit(RLIMIT_NOFILE, 64);
    set_limit(RLIMIT_FSIZE, (rlim_t)tmp_mib*1024*1024);
    set_limit(RLIMIT_CORE, 0);
    set_limit(RLIMIT_CPU, (rlim_t)wall_sec + 1);
    drop_capabilities(highest_cap);
    install_seccomp();
    // close_range is required to prevent accidental host file descriptor inheritance.
    if (syscall(SYS_close_range, 3U, ~0U, 0U) != 0) FAIL("close_range");
    if (clearenv() != 0) FAIL("clearenv");
    if (setenv("PATH", "/usr/bin:/bin", 1) || setenv("HOME", "/", 1) || setenv("LANG", "C", 1)) FAIL("guest environment");
    execv(argv[0], argv);
    FAIL("guest execve");
}

static unsigned long parse_ul(const char *s, unsigned long min, unsigned long max) {
    if (!s || !*s || *s=='-') { errno=EINVAL; FAIL("invalid numeric argument"); }
    char *end = NULL;
    errno=0;
    unsigned long value = strtoul(s, &end, 10);
    if (errno || !end || *end || value < min || value > max) { errno=EINVAL; FAIL("out-of-range argument"); }
    return value;
}

int main(int argc, char **argv) {
    if (argc < 8 || strcmp(argv[1], "--rootfs") || strcmp(argv[3], "--tmp-mib") || strcmp(argv[5], "--wall-sec") || strcmp(argv[7], "--")) {
        fputs("usage: sentinel-sandbox-init --rootfs /pinned/rootfs --tmp-mib N --wall-sec N -- /guest/program [fixed args]\n", stderr);
        return 125;
    }
    if (argc < 9 || argv[8][0] != '/' || geteuid() == 0 || getuid() == 0) {
        fputs("only non-root operator and an absolute trusted guest executable are allowed\n", stderr);
        return 125;
    }
    unsigned long tmp_mib = parse_ul(argv[4], 16, 1024);
    unsigned long wall_sec = parse_ul(argv[6], 1, 1800);
    if (argv[2][0] != '/') { fputs("rootfs must be absolute\n", stderr); return 125; }
    struct stat root;
    if (lstat(argv[2], &root) != 0 || !S_ISDIR(root.st_mode) || (root.st_mode & 022) || root.st_uid != 0) {
        fputs("rootfs must be an ordinary root-owned, non-group-writable directory\n", stderr);
        return 125;
    }
    // Mandatory pipe handoff: worker first applies cgroup limits, then grants one byte.
    char gate;
    if (read(3, &gate, 1) != 1 || gate != '!') { fputs("cgroup gate missing\n", stderr); return 125; }
    if (close(3) != 0) FAIL("close gate");
    int highest_cap = cap_last_cap();
    uid_t outside_uid = geteuid(); gid_t outside_gid = getegid();
    if (unshare(CLONE_NEWUSER) != 0) FAIL("unshare user");
    char mapping[80];
    if (snprintf(mapping, sizeof(mapping), "0 %u 1\n", (unsigned)outside_uid) >= (int)sizeof(mapping)) _exit(125);
    write_file("/proc/self/uid_map", mapping);
    write_file("/proc/self/setgroups", "deny");
    if (snprintf(mapping, sizeof(mapping), "0 %u 1\n", (unsigned)outside_gid) >= (int)sizeof(mapping)) _exit(125);
    write_file("/proc/self/gid_map", mapping);
    if (setresgid(0,0,0) || setresuid(0,0,0)) FAIL("apply guest credentials");
    if (unshare(CLONE_NEWNS|CLONE_NEWNET|CLONE_NEWIPC|CLONE_NEWUTS|CLONE_NEWPID) != 0) FAIL("unshare isolation");
    pid_t pid = fork();
    if (pid < 0) FAIL("fork guest PID1");
    if (pid == 0) enter_guest(argv[2], tmp_mib, wall_sec, &argv[8], highest_cap);
    int status;
    if (waitpid(pid, &status, 0) < 0) FAIL("waitpid guest");
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 125;
}
