//spdx license lgpl
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

#define MAX_ARGS   64
#define SOCK_PATH  "/dev/nssu.sock"

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
int init_child = 1; // Android init PID

// ---------- helpers ----------
static void setup_filesystems(int use_devtmpfs) {
    if (mount("proc", "/proc", "proc", MS_NOEXEC|MS_NOSUID|MS_NODEV, "") < 0 && errno != EBUSY)
        perror("mount /proc");
    if (mount("sysfs", "/sys", "sysfs", MS_NOEXEC|MS_NOSUID|MS_NODEV, "") < 0 && errno != EBUSY)
        perror("mount /sys");

    if (use_devtmpfs) {
        if (mount("devtmpfs", "/dev", "devtmpfs", 0, "mode=0755") < 0 && errno != EBUSY)
            perror("mount devtmpfs");
    } else {
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
}

static void sigchld_handler(int sig) {
    (void)sig;
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (WIFEXITED(status))
            fprintf(stderr, "child %d exited code=%d\n", pid, WEXITSTATUS(status));
        else if (WIFSIGNALED(status))
            fprintf(stderr, "child %d killed signal=%d\n", pid, WTERMSIG(status));
    }
}

// ---------- TLV helpers ----------
static void send_tlv(int sock, uint8_t type, const char *val) {
    uint16_t len = (uint16_t)strlen(val);
    write(sock, &type, 1);
    write(sock, &len, 2);
    write(sock, val, len);
}

static char *recv_tlv(int sock, uint8_t *out_type) {
    uint8_t type;
    uint16_t len;
    if (read(sock, &type, 1) != 1) return NULL;
    if (read(sock, &len, 2) != 2) return NULL;
    char *buf = malloc(len+1);
    if (!buf) return NULL;
    if (read(sock, buf, len) != len) { free(buf); return NULL; }
    buf[len] = 0;
    if (out_type) *out_type = type;
    return buf;
}
// ---------- proxy socket loop ----------
void proxy_loop(void) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); exit(1); }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, SOCK_PATH);
    unlink(addr.sun_path);
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }
    if (listen(sock, 5) < 0) {
        perror("listen");
        exit(1);
    }

    while (1) {
        int client = accept(sock, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        char *tag=NULL,*newroot=NULL,*oldroot=NULL;
        char *argv[MAX_ARGS]; int argc=0;
        uint8_t type;
        while (1) {
            char *val = recv_tlv(client,&type);
            if (!val) break;
            switch(type) {
            case TLV_TAG: tag=val; break;
            case TLV_NEWROOT: newroot=val; break;
            case TLV_OLDROOT: oldroot=val; break;
            case TLV_ARG: argv[argc++]=val; break;
            }
        }
        argv[argc]=NULL;

        pid_t child=-1;
        if (tag && strcmp(tag,"NS_SU")==0)
            child = spawn_common(MODE_NS_SU,newroot,oldroot,argv);
        else if (tag && strcmp(tag,"NS_CHROOT")==0)
            child = spawn_common(MODE_NS_CHROOT,newroot,oldroot,argv);
        else if (tag && strcmp(tag,"NS_CHROOT_DEVTMPFS")==0)
            child = spawn_common(MODE_NS_CHROOT_DEVTMPFS,newroot,oldroot,argv);

        write(client,&child,sizeof(child));
        close(client);

        if (tag) free(tag);
        if (newroot) free(newroot);
        if (oldroot) free(oldroot);
        for (int i=0;i<argc;i++) free(argv[i]);
    }
}

// ---------- spawn_common ----------
pid_t spawn_common(int mode, const char *newroot, const char *oldroot, char **argv) {
    pid_t pid = fork();
    if (pid < 0) return -1;

    if (pid == 0) {
        switch (mode) {
        case MODE_PROXY:
            if (unshare(CLONE_NEWNS) < 0) { perror("unshare proxy"); _exit(1); }
            setup_filesystems(0);
            proxy_loop(); // proxy child enters receive loop
            _exit(0);
        case MODE_NS_CHROOT:
            if (unshare(CLONE_NEWPID | CLONE_NEWNS) < 0) { perror("unshare chroot"); _exit(1); }
            setup_filesystems(0);
            break;
        case MODE_NS_CHROOT_DEVTMPFS:
            if (unshare(CLONE_NEWNS) < 0) { perror("unshare chroot-devtmpfs"); _exit(1); }
            setup_filesystems(1);
            break;
        case MODE_NS_SU:
            break;
        }

        if (mode == MODE_NS_SU) {
            char ns_path[64];
            snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/pid", init_child);
            int fd = open(ns_path, O_RDONLY);
            if (fd >= 0) {
                if (setns(fd, CLONE_NEWPID) < 0) perror("setns");
                close(fd);
            }
            if (argv && argv[0]) execvp(argv[0], argv);
            perror("execvp ns-su");
            _exit(127);
        } else if (mode == MODE_NS_CHROOT || mode == MODE_NS_CHROOT_DEVTMPFS) {
            if (newroot) {
                if (chdir(newroot) < 0) { perror("chdir newroot"); _exit(1); }
                const char *old = oldroot ? oldroot : "oldroot";
                mkdir(old, 0755);
                if (pivot_root(".", old) < 0) { perror("pivot_root"); _exit(1); }
                if (chdir("/") < 0) { perror("chdir /"); _exit(1); }
            }
            if (argv && argv[0]) execvp(argv[0], argv);
            perror("execvp ns-chroot");
            _exit(127);
        }
        _exit(0);
    }
    return pid;
}

// ---------- socket helper ----------
pid_t sock_send_request(const char *tag,
                        const char *newroot,
                        const char *oldroot,
                        char **argv,
                        int argc)
{
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return -1; }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, SOCK_PATH);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }

    send_tlv(sock, TLV_TAG, tag);
    if (newroot) send_tlv(sock, TLV_NEWROOT, newroot);
    if (oldroot) send_tlv(sock, TLV_OLDROOT, oldroot);
    for (int i = 0; i < argc; i++) send_tlv(sock, TLV_ARG, argv[i]);

    pid_t child = -1;
    if (read(sock, &child, sizeof(child)) != sizeof(child)) {
        perror("read child pid");
        child = -1;
    }
    close(sock);
    return child;
}
// ---------- main_rdinit ----------
int main_rdinit(void) {
    fprintf(stderr, "rdinit proxy starting...\n");

    // Parent sets up devtmpfs baseline
    setup_filesystems(1);

    // Spawn proxy child (mount namespace + socket loop)
    pid_t proxy = spawn_common(MODE_PROXY, NULL, NULL, NULL);
    if (proxy < 0) { perror("spawn proxy"); exit(1); }
    fprintf(stderr, "proxy child pid=%d\n", proxy);

    signal(SIGCHLD, sigchld_handler);

    // Wait until proxy socket is ready (retry instead of fixed sleep)
    int retries = 10;
    while (retries-- > 0) {
        if (access(SOCK_PATH, F_OK) == 0) break;
        usleep(100000); // 100ms
    }

    // Send request to proxy: chroot-devtmpfs with /init
    char *argv_init[] = { "/init", NULL };
    pid_t child = sock_send_request("NS_CHROOT_DEVTMPFS", "/", "oldroot", argv_init, 1);
    if (child < 0) { perror("sock_send_request /init"); exit(1); }
    init_child = child;
    fprintf(stderr, "spawned Android init pid=%d\n", init_child);

    // Parent just waits for signals, proxy handles requests
    while (1) pause();
    return 0;
}

// ---------- dispatcher ----------
int main(int argc, char *argv[]) {
    const char *execname = strrchr(argv[0], '/');
    execname = execname ? execname + 1 : argv[0];

    for (int i = 1; i < argc; ++i)
        if (strcmp(argv[i], "--debug") == 0) debug_mode = 1;

    if (strcmp(execname, "rdinit") == 0) {
        // Only run rdinit logic if PID == 1 (init) or debug mode enabled
        if (getpid() == 1 || debug_mode) {
            return main_rdinit();
        } else {
            fprintf(stderr, "rdinit must run as PID 1 or with --debug\n");
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
        fprintf(stderr, "unknown invocation %s\n", execname);
        return 1;
    }
}
