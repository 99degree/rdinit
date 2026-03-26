#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdarg.h>

#define MAX_ARGS   64
#define ABSTRACT_SOCK_NAME "nssu_abstract_v1"

// TLV tags
#define TLV_TAG      0x01
#define TLV_ARG      0x02
#define TLV_NEWROOT  0x03
#define TLV_OLDROOT  0x04

// Modes
#define MODE_PROXY               1
#define MODE_NS_SU               2
#define MODE_NS_CHROOT           3
#define MODE_NS_CHROOT_DEVTMPFS  4

pid_t spawn_common(int mode, const char *newroot, const char *oldroot, char **argv);

int debug_mode = 0;
int init_child = 1; // Android init PID

// ---------- logging ----------
static int log_enabled = 1;

static void log_msg(const char *fmt, ...) {
    if (!log_enabled) return;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[rdinit] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

#define LOG(...) log_msg(__VA_ARGS__)

// ---------- helpers ----------
static void setup_filesystems(int use_devtmpfs) {
    LOG("setup_filesystems begin (use_devtmpfs=%d)", use_devtmpfs);
    if (mount("proc", "/proc", "proc", MS_NOEXEC|MS_NOSUID|MS_NODEV, "") < 0 && errno != EBUSY)
        perror("mount /proc");
    if (mount("sysfs", "/sys", "sysfs", MS_NOEXEC|MS_NOSUID|MS_NODEV, "") < 0 && errno != EBUSY)
        perror("mount /sys");

    if (use_devtmpfs) {
        LOG("mounting devtmpfs");
        if (mount("devtmpfs", "/dev", "devtmpfs", 0, "mode=0755") < 0 && errno != EBUSY)
            perror("mount devtmpfs");
    } else {
        LOG("mounting tmpfs for /dev");
        if (mount("tmpfs", "/dev", "tmpfs", 0, "mode=0755,size=64M") < 0 && errno != EBUSY)
            perror("mount tmpfs /dev");
        mknod("/dev/null",    S_IFCHR | 0666, makedev(1, 3));
        mknod("/dev/zero",    S_IFCHR | 0666, makedev(1, 5));
        mknod("/dev/full",    S_IFCHR | 0666, makedev(1, 7));
        mknod("/dev/random",  S_IFCHR | 0666, makedev(1, 8));
        mknod("/dev/urandom", S_IFCHR | 0666, makedev(1, 9));
        mknod("/dev/tty",     S_IFCHR | 0666, makedev(5, 0));
        mknod("/dev/console", S_IFCHR | 0600, makedev(5, 1));
    }
    LOG("setup_filesystems done");
}

static void sigchld_handler(int sig) {
    (void)sig;
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (WIFEXITED(status))
            LOG("child %d exited code=%d", pid, WEXITSTATUS(status));
        else if (WIFSIGNALED(status))
            LOG("child %d killed signal=%d (%s)", pid, WTERMSIG(status), strsignal(WTERMSIG(status)));
    }
}

// ---------- TLV helpers ----------
static ssize_t write_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = buf;
    size_t left = len;
    while (left) {
        ssize_t w = write(fd, p, left);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        left -= w;
        p += w;
    }
    return len;
}

static ssize_t read_all(int fd, void *buf, size_t len) {
    uint8_t *p = buf;
    size_t left = len;
    while (left) {
        ssize_t r = read(fd, p, left);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return (ssize_t)(len - left);
        left -= r;
        p += r;
    }
    return len;
}

static void send_tlv(int sock, uint8_t type, const char *val) {
    uint16_t len = (uint16_t)strlen(val);
    write_all(sock, &type, 1);
    write_all(sock, &len, 2);
    write_all(sock, val, len);
}

static char *recv_tlv(int sock, uint8_t *out_type) {
    uint8_t type;
    uint16_t len;
    if (read_all(sock, &type, 1) != 1) return NULL;
    if (read_all(sock, &len, 2) != 2) return NULL;
    char *buf = malloc(len+1);
    if (!buf) return NULL;
    if (read_all(sock, buf, len) != len) { free(buf); return NULL; }
    buf[len] = 0;
    if (out_type) *out_type = type;
    return buf;
}

// ---------- proxy socket loop ----------
void proxy_loop(void) {
    LOG("proxy_loop starting");
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); exit(1); }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    size_t name_len = strlen(ABSTRACT_SOCK_NAME);
    addr.sun_path[0] = '\0';
    memcpy(&addr.sun_path[1], ABSTRACT_SOCK_NAME, name_len);
    socklen_t bind_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + name_len);

    LOG("binding abstract socket");
    if (bind(sock, (struct sockaddr*)&addr, bind_len) < 0) {
        perror("bind (abstract)");
        exit(1);
    }
    LOG("listening");
    if (listen(sock, 5) < 0) {
        perror("listen");
        exit(1);
    }

    while (1) {
        LOG("waiting for client");
        int client = accept(sock, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }
        LOG("accepted client");
        // ... rest unchanged
    }
}

// ---------- spawn_common ----------
pid_t spawn_common(int mode, const char *newroot, const char *oldroot, char **argv) {
    LOG("spawn_common mode=%d", mode);
    pid_t pid = fork();
    if (pid < 0) return -1;

    if (pid == 0) {
        switch (mode) {
        case MODE_PROXY:
            LOG("calling unshare(CLONE_NEWNS)");
            if (unshare(CLONE_NEWNS) < 0) { perror("unshare proxy"); _exit(1); }
            LOG("unshare succeeded");
            setup_filesystems(0);
            proxy_loop();
            _exit(0);
        case MODE_NS_CHROOT:
            LOG("calling unshare(CLONE_NEWPID|CLONE_NEWNS)");
            if (unshare(CLONE_NEWPID | CLONE_NEWNS) < 0) { perror("unshare chroot"); _exit(1); }
            LOG("unshare succeeded");
            setup_filesystems(0);
            break;
        // ... rest unchanged, add LOG around pivot_root, chroot, etc.
        }
    }
    return pid;
}

// ---------- sock_send_request ----------
pid_t sock_send_request(const char *tag,
                        const char *newroot,
                        const char *oldroot,
                        char **argv,
                        int argc)
{
    LOG("sock_send_request tag=%s newroot=%s oldroot=%s argc=%d",
        tag, newroot ? newroot : "(null)", oldroot ? oldroot : "(null)", argc);

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return -1; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    size_t name_len = strlen(ABSTRACT_SOCK_NAME);
    if (name_len + 1 > sizeof(addr.sun_path)) {
        LOG("abstract name too long");
        close(sock);
        return -1;
    }
    addr.sun_path[0] = '\0';
    memcpy(&addr.sun_path[1], ABSTRACT_SOCK_NAME, name_len);
    socklen_t addr_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + name_len);

    if (connect(sock, (struct sockaddr*)&addr, addr_len) < 0) {
        perror("connect (abstract)");
        close(sock);
        return -1;
    }

    send_tlv(sock, TLV_TAG, tag);
    if (newroot) send_tlv(sock, TLV_NEWROOT, newroot);
    if (oldroot) send_tlv(sock, TLV_OLDROOT, oldroot);
    for (int i = 0; i < argc; i++) send_tlv(sock, TLV_ARG, argv[i]);

    pid_t child = -1;
    if (read_all(sock, &child, sizeof(child)) != sizeof(child)) {
        perror("read child pid");
        child = -1;
    }
    close(sock);
    LOG("sock_send_request returning child pid=%d", child);
    return child;
}

// ---------- main_rdinit ----------
int main_rdinit(void) {
    LOG("rdinit proxy starting...");

    setup_filesystems(1);

    pid_t proxy = spawn_common(MODE_PROXY, NULL, NULL, NULL);
    if (proxy < 0) { perror("spawn proxy"); exit(1); }
    LOG("proxy child pid=%d", proxy);

    signal(SIGCHLD, sigchld_handler);

    int retries = 20;
    while (retries-- > 0) {
        int s = socket(AF_UNIX, SOCK_STREAM, 0);
        if (s >= 0) {
            struct sockaddr_un addr;
            memset(&addr, 0, sizeof(addr));
            addr.sun_family = AF_UNIX;
            size_t name_len = strlen(ABSTRACT_SOCK_NAME);
            addr.sun_path[0] = '\0';
            memcpy(&addr.sun_path[1], ABSTRACT_SOCK_NAME, name_len);
            socklen_t addr_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + name_len);
            if (connect(s, (struct sockaddr*)&addr, addr_len) == 0) {
                close(s);
                break;
            }
            close(s);
        }
        usleep(100000);
    }

    char *argv_init[] = { "/init", NULL };
    pid_t child = sock_send_request("NS_CHROOT_DEVTMPFS", "/", "oldroot", argv_init, 1);
    if (child < 0) { perror("sock_send_request /init"); exit(1); }
    init_child = child;
    LOG("spawned Android init pid=%d", init_child);

    while (1) pause();
    return 0;
}

// ---------- dispatcher ----------
int main(int argc, char *argv[]) {
    const char *execname = strrchr(argv[0], '/');
    execname = execname ? execname + 1 : argv[0];

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--debug") == 0) debug_mode = 1;
        if (strcmp(argv[i], "--quiet") == 0) log_enabled = 0;
    }

    LOG("dispatcher invoked as %s", execname);

    if (strcmp(execname, "rdinit") == 0) {
        if (getpid() == 1 || debug_mode) {
            return main_rdinit();
        } else {
            LOG("rdinit must run as PID 1 or with --debug");
            return 1;
        }
    } else if (strcmp(execname, "ns-su") == 0) {
        if (argc < 2) { fprintf(stderr,"Usage: ns-su <binary> [args...]\n"); return 1; }
        char *child_argv[MAX_ARGS]; int n=0;
        for (int i=1;i<argc && n<MAX_ARGS-1;i++) child_argv[n++]=argv[i];
        child_argv[n]=NULL;
        pid_t child = sock_send_request("NS_SU",NULL,NULL,child_argv,n);
        printf("Proxy spawned ns-su pid=%d\n",child);
        return 0;
    } else if (strcmp(execname, "ns-chroot") == 0) {
        if (argc < 3) { fprintf(stderr,"Usage: ns-chroot <root> <binary> [args...]\n"); return 1; }
        char *child_argv[MAX_ARGS]; int n=0;
        for (int i=2;i<argc && n<MAX_ARGS-1;i++) child_argv[n++]=argv[i];
        child_argv[n]=NULL;
        pid_t child = sock_send_request("NS_CHROOT",argv[1],"oldroot",child_argv,n);
        printf("Proxy spawned ns-chroot pid=%d\n",child);
        return 0;
    } else {
        LOG("unknown invocation %s", execname);
        return 1;
    }
}
