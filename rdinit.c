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

int debug_mode = 0;
int init_child = -1;
static int log_enabled = 1;
static __thread const char *log_prefix = NULL;

pid_t spawn_common(int mode,const char *newroot,const char *oldroot,char **argv);

void set_log_prefix(const char *prefix) { log_prefix = prefix; }

static void log_msg(const char *fmt, ...) {
    if (!log_enabled) return;
    const char *prefix = log_prefix ? log_prefix : "rdinit";
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[%s] ", prefix);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}
#define LOG(...) log_msg(__VA_ARGS__)

// ---------- signals ----------
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

// ---------- filesystem setup ----------
static void setup_filesystems(int use_devtmpfs) {
    if (debug_mode) {
        LOG("debug_mode enabled: forcing tmpfs for /dev");
        use_devtmpfs = 0;
    }
    mount("proc", "/proc", "proc", MS_NOEXEC|MS_NOSUID|MS_NODEV, "");
    mount("sysfs", "/sys", "sysfs", MS_NOEXEC|MS_NOSUID|MS_NODEV, "");
    if (use_devtmpfs) {
        mount("devtmpfs", "/dev", "devtmpfs", 0, "mode=0755");
    } else {
        mount("tmpfs", "/dev", "tmpfs", 0, "mode=0755,size=64M");
        mknod("/dev/null",    S_IFCHR | 0666, makedev(1, 3));
        mknod("/dev/zero",    S_IFCHR | 0666, makedev(1, 5));
        mknod("/dev/full",    S_IFCHR | 0666, makedev(1, 7));
        mknod("/dev/random",  S_IFCHR | 0666, makedev(1, 8));
        mknod("/dev/urandom", S_IFCHR | 0666, makedev(1, 9));
        mknod("/dev/tty",     S_IFCHR | 0666, makedev(5, 0));
        mknod("/dev/console", S_IFCHR | 0600, makedev(5, 1));
    }
}

// ---------- TLV helpers ----------
static ssize_t write_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = buf;
    size_t left = len;
    while (left) {
        ssize_t w = write(fd, p, left);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        left -= w; p += w;
    }
    return len;
}

static ssize_t read_all(int fd, void *buf, size_t len) {
    uint8_t *p = buf;
    size_t left = len;
    while (left) {
        ssize_t r = read(fd, p, left);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return (ssize_t)(len - left);
        left -= r; p += r;
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
    uint8_t type; uint16_t len;
    if (read_all(sock, &type, 1) != 1) return NULL;
    if (read_all(sock, &len, 2) != 2) return NULL;
    char *buf = malloc(len+1);
    if (!buf) return NULL;
    if (read_all(sock, buf, len) != len) { free(buf); return NULL; }
    buf[len] = 0;
    if (out_type) *out_type = type;
    return buf;
}
// ---------- proxy_loop ----------
void proxy_loop(void) {
    set_log_prefix("proxy");
    LOG("proxy_loop starting");

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return; }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    size_t name_len = strlen(ABSTRACT_SOCK_NAME);
    addr.sun_path[0] = '\0';
    memcpy(&addr.sun_path[1], ABSTRACT_SOCK_NAME, name_len);
    socklen_t bind_len = offsetof(struct sockaddr_un, sun_path) + 1 + name_len;

    if (bind(sock, (struct sockaddr*)&addr, bind_len) < 0) {
        perror("bind (abstract)");
        close(sock);
        return;
    }
    if (listen(sock, 5) < 0) {
        perror("listen");
        close(sock);
        return;
    }

    while (1) {
        int client = accept(sock, NULL, NULL);
        if (client < 0) { if (errno == EINTR) continue; continue; }

        char *tag=NULL,*newroot=NULL,*oldroot=NULL,*argv[MAX_ARGS]; int argc=0;
        uint8_t type;
        while (1) {
            char *val = recv_tlv(client,&type);
            if (!val) break;
            switch(type){
                case TLV_TAG: tag=val; break;
                case TLV_NEWROOT: newroot=val; break;
                case TLV_OLDROOT: oldroot=val; break;
                case TLV_ARG: if(argc<MAX_ARGS-1) argv[argc++]=val; break;
                default: free(val); break;
            }
        }
        argv[argc]=NULL;

        int mode=-1;
        if(tag){
            if(strcmp(tag,"NS_SU")==0) mode=MODE_NS_SU;
            else if(strcmp(tag,"NS_CHROOT")==0) mode=MODE_NS_CHROOT;
            else if(strcmp(tag,"NS_CHROOT_DEVTMPFS")==0) mode=MODE_NS_CHROOT_DEVTMPFS;
            else if(strcmp(tag,"PROXY")==0) mode=MODE_PROXY;
        }

        pid_t child=-EINVAL;
        if(mode>0) child=spawn_common(mode,newroot,oldroot,argv);
        write_all(client,&child,sizeof(child));

        free(tag); free(newroot); free(oldroot);
        for(int i=0;i<argc;i++) free(argv[i]);
        close(client);
    }
}

// ---------- spawn_common ----------
static int file_exists(const char *path) {
    struct stat st; return (stat(path,&st)==0 && S_ISREG(st.st_mode));
}

pid_t spawn_common(int mode,const char *newroot,const char *oldroot,char **argv){
    if(argv && argv[0] && !file_exists(argv[0])) return -ENOENT;

    pid_t pid=fork();
    if(pid<0) return -1;
    if(pid==0){
        set_log_prefix("child");
        switch(mode){
            case MODE_PROXY:
                if(unshare(CLONE_NEWNS)<0) exit(1);
                if(mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)<0) exit(1);
                setup_filesystems(0);
                proxy_loop(); exit(0);
            case MODE_NS_SU:
                execvp(argv[0],argv); exit(127);
            case MODE_NS_CHROOT:
            case MODE_NS_CHROOT_DEVTMPFS:
                if(chdir(newroot)<0) exit(1);
                if(chroot(newroot)<0) exit(1);
                execvp(argv[0],argv); exit(127);
            default:
                exit(1);
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
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    size_t name_len = strlen(ABSTRACT_SOCK_NAME);
    addr.sun_path[0] = '\0';
    memcpy(&addr.sun_path[1], ABSTRACT_SOCK_NAME, name_len);
    socklen_t addr_len = offsetof(struct sockaddr_un, sun_path) + 1 + name_len;

    if (connect(sock, (struct sockaddr*)&addr, addr_len) < 0) {
        close(sock); return -1;
    }

    send_tlv(sock, TLV_TAG, tag);
    if (newroot) send_tlv(sock, TLV_NEWROOT, newroot);
    if (oldroot) send_tlv(sock, TLV_OLDROOT, oldroot);
    for (int i = 0; i < argc; i++) send_tlv(sock, TLV_ARG, argv[i]);

    pid_t child=-1;
    if(read_all(sock,&child,sizeof(child))!=sizeof(child)) child=-1;
    close(sock);
    return child;
}
// ---------- main_rdinit ----------
int main_rdinit(int argc, char **argv) {
    set_log_prefix("rdinit");

    // Handle --help
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: rdinit [options] [init_binary [args...]]\n\n");
            printf("Options:\n");
            printf("  --help       Show this help message\n");
            printf("  --debug      Enable debug logging\n");
            printf("  --quiet      Disable logging\n\n");
            printf("If no init_binary is specified, defaults to /init.\n");
            return 0;
        }
    }

    LOG("rdinit proxy starting...");

    if (unshare(CLONE_NEWNS) < 0) { perror("unshare(CLONE_NEWNS)"); return 1; }
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) { perror("mount --make-rprivate /"); return 1; }

    setup_filesystems(1);

    pid_t proxy = spawn_common(MODE_PROXY, NULL, NULL, NULL);
    if (proxy < 0) { fprintf(stderr, "spawn proxy failed\n"); return 1; }
    signal(SIGCHLD, sigchld_handler);

    // Wait until proxy socket is ready
    int retries = 20;
    while (retries-- > 0) {
        int s = socket(AF_UNIX, SOCK_STREAM, 0);
        if (s >= 0) {
            struct sockaddr_un addr; memset(&addr, 0, sizeof(addr));
            addr.sun_family = AF_UNIX;
            size_t name_len = strlen(ABSTRACT_SOCK_NAME);
            addr.sun_path[0] = '\0';
            memcpy(&addr.sun_path[1], ABSTRACT_SOCK_NAME, name_len);
            socklen_t addr_len = offsetof(struct sockaddr_un, sun_path) + 1 + name_len;
            if (connect(s, (struct sockaddr*)&addr, addr_len) == 0) { close(s); break; }
            close(s);
        }
        usleep(100000);
    }

    char *init_path = (argc > 1) ? argv[1] : "/init";
    char *child_argv[MAX_ARGS]; int n = 0;
    child_argv[n++] = init_path;
    for (int i = 2; i < argc && n < MAX_ARGS - 1; i++) child_argv[n++] = argv[i];
    child_argv[n] = NULL;

    pid_t child = sock_send_request("NS_CHROOT_DEVTMPFS", "/", "oldroot", child_argv, n);
    if (child < 0) { fprintf(stderr, "sock_send_request failed for %s\n", init_path); return 1; }
    init_child = child;

    while (1) {
        int status; pid_t pid = waitpid(-1, &status, 0);
        if (pid < 0) { if (errno == EINTR) continue; perror("waitpid"); break; }
        if (WIFEXITED(status)) LOG("child %d exited code=%d", pid, WEXITSTATUS(status));
        else if (WIFSIGNALED(status)) LOG("child %d killed signal=%d (%s)", pid, WTERMSIG(status), strsignal(WTERMSIG(status)));
    }
    return 0;
}

// ---------- main_ns_su ----------
int main_ns_su(int argc, char *argv[]) {
    set_log_prefix("ns-su");

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: ns-su [options] <binary> [args...]\n\n");
            printf("Options:\n");
            printf("  --help       Show this help message\n");
            printf("  --debug      Enable debug logging\n");
            printf("  --quiet      Disable logging\n\n");
            return 0;
        }
    }

    if (argc < 2) { fprintf(stderr,"Usage: ns-su <binary> [args...]\n"); return 1; }

    char *child_argv[MAX_ARGS]; int n = 0;
    for (int i = 1; i < argc && n < MAX_ARGS - 1; i++) child_argv[n++] = argv[i];
    child_argv[n] = NULL;

    pid_t child = sock_send_request("NS_SU", NULL, NULL, child_argv, n);
    if (child < 0) { fprintf(stderr, "ns-su failed\n"); return 1; }

    printf("Proxy spawned ns-su pid=%d\n", child);
    return 0;
}

// ---------- main_ns_chroot ----------
int main_ns_chroot(int argc, char *argv[]) {
    set_log_prefix("ns-chroot");

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: ns-chroot [options] <root> <binary> [args...]\n\n");
            printf("Options:\n");
            printf("  --help       Show this help message\n");
            printf("  --debug      Enable debug logging\n");
            printf("  --quiet      Disable logging\n\n");
            return 0;
        }
    }

    if (argc < 3) { fprintf(stderr,"Usage: ns-chroot <root> <binary> [args...]\n"); return 1; }

    char *child_argv[MAX_ARGS]; int n = 0;
    for (int i = 2; i < argc && n < MAX_ARGS - 1; i++) child_argv[n++] = argv[i];
    child_argv[n] = NULL;

    pid_t child = sock_send_request("NS_CHROOT", argv[1], "oldroot", child_argv, n);
    if (child < 0) { fprintf(stderr, "ns-chroot failed\n"); return 1; }

    printf("Proxy spawned ns-chroot pid=%d\n", child);
    return 0;
}
// ---------- dispatcher ----------
int main(int argc, char *argv[]) {
    const char *execname = strrchr(argv[0], '/');
    execname = execname ? execname + 1 : argv[0];

    // Global options
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--debug") == 0) debug_mode = 1;
        if (strcmp(argv[i], "--quiet") == 0) log_enabled = 0;
        if (strcmp(argv[i], "--help") == 0) {
            printf("Supported subcommands:\n");
            printf("  rdinit     - start proxy and spawn init (/init by default)\n");
            printf("  ns-su      - run a binary inside proxy namespace\n");
            printf("  ns-chroot  - run a binary inside a chroot namespace\n\n");
            printf("You can invoke directly (e.g. 'ns-su') or via rdinit:\n");
            printf("  rdinit ns-su <binary> [args...]\n");
            printf("  rdinit ns-chroot <root> <binary> [args...]\n");
            return 0;
        }
    }

    // Normal invocation by binary name
    if (strcmp(execname, "rdinit") == 0) {
        // Check if rdinit is being used as a front-end for subcommands
        if (argc > 1 && strcmp(argv[1], "ns-su") == 0) {
            return main_ns_su(argc - 1, argv + 1);
        } else if (argc > 1 && strcmp(argv[1], "ns-chroot") == 0) {
            return main_ns_chroot(argc - 1, argv + 1);
        } else {
            return main_rdinit(argc, argv);
        }
    } else if (strcmp(execname, "ns-su") == 0) {
        return main_ns_su(argc, argv);
    } else if (strcmp(execname, "ns-chroot") == 0) {
        return main_ns_chroot(argc, argv);
    } else {
        set_log_prefix("unknown");
        LOG("unknown invocation %s", execname);
        fprintf(stderr, "Supported subcommands: rdinit, ns-su, ns-chroot\n");
        return 1;
    }
}
