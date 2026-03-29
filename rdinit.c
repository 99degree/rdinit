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
#define TLV_END      0xFF   // end marker

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

static int kmsg_fd = -1;

static void log_msg(const char *fmt, ...) {
    if (!log_enabled) return;
    const char *prefix = log_prefix ? log_prefix : "rdinit";
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[%s] ", prefix);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);

    if (kmsg_fd >= 0) {
        va_start(ap, fmt);
        dprintf(kmsg_fd, "<6>[%s] ", prefix);
        vdprintf(kmsg_fd, fmt, ap);
        dprintf(kmsg_fd, "\n");
        va_end(ap);
    }
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

static void setup_console(void) {
int fd = open("/dev/console", O_WRONLY);
if (fd >= 0) {
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    close(fd);
}
setvbuf(stdout, NULL, _IONBF, 0);  // disable buffering
setvbuf(stderr, NULL, _IONBF, 0);

kmsg_fd = open("/dev/kmsg", O_WRONLY);
if (kmsg_fd >= 0) {
    int flags = fcntl(kmsg_fd, F_GETFD);
    fcntl(kmsg_fd, F_SETFD, flags | FD_CLOEXEC);
    dprintf(kmsg_fd, "<6>[xxx] kmsg logging enabled\n");
}
}
// ---------- filesystem setup ----------
static void setup_filesystems(int use_devtmpfs) {
    if (debug_mode) {
        LOG("debug_mode enabled: forcing tmpfs for /dev");
        use_devtmpfs = 0;
    }
    mount("proc", "/proc", "proc", MS_NOEXEC|MS_NOSUID|MS_NODEV, "");
     // There is complain about /sys busy so don't mount it.
    //mount("sysfs", "/sys", "sysfs", MS_NOEXEC|MS_NOSUID|MS_NODEV, "");
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

// Extra sinks
    mknod("/dev/pmsg0",   S_IFCHR | 0666, makedev(10, 224));
    mknod("/dev/kmsg",    S_IFCHR | 0666, makedev(1, 11));
    mknod("/dev/ttyGS0",  S_IFCHR | 0666, makedev(253, 0));
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
    if (len > 0) write_all(sock, val, len);
}

static char *recv_tlv(int sock, uint8_t *out_type) {
    uint8_t type; uint16_t len;
    if (read_all(sock, &type, 1) != 1) return NULL;
    if (read_all(sock, &len, 2) != 2) return NULL;
    char *buf = malloc(len+1);
    if (!buf) return NULL;
    if (len > 0 && read_all(sock, buf, len) != len) { free(buf); return NULL; }
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
        LOG("proxy_loop accepting sock");
        int client = accept(sock, NULL, NULL);
        if (client < 0) { if (errno == EINTR) continue; continue; }

LOG("proxy_loop arrival sock data");

        char *tag=NULL,*newroot=NULL,*oldroot=NULL,*argv[MAX_ARGS]; int argc=0;
        uint8_t type;
        int tag_count = 0;

        while (1) {
            char *val = recv_tlv(client,&type);
            if (!val) break;

            if (type == TLV_END) {
LOG("proxy_loop sock tlv end");                free(val);
                break; 
            }
            tag_count++;
            if (tag_count > 10) { LOG("Too many TLVs"); free(val); break; }

            switch(type){
                case TLV_TAG: tag=val; break;
                case TLV_NEWROOT: newroot=val; break;
                case TLV_OLDROOT: oldroot=val; break;
                case TLV_ARG: if(argc<MAX_ARGS-1) argv[argc++]=val; break;
                default: free(val); break;
            }
        }
        argv[argc]=NULL;

LOG("proxy_loop parsed tlc %s %s %s", tag, argv[0], argv[1]);

        int mode=-1;
        if(tag){
            if(strcmp(tag,"NS_SU")==0) mode=MODE_NS_SU;
            else if(strcmp(tag,"NS_CHROOT")==0) mode=MODE_NS_CHROOT;
            else if(strcmp(tag,"NS_CHROOT_DEVTMPFS")==0) mode=MODE_NS_CHROOT_DEVTMPFS;
            else if(strcmp(tag,"PROXY")==0) mode=MODE_PROXY;
        }

        LOG("proxy_loop doing mode %s", tag ? tag : "(null)");

        pid_t child=-EINVAL;
        if(mode>0) child=spawn_common(mode,newroot,oldroot,argv);
       LOG("proxy_loop spawn_common %d", child);
        write_all(client,&child,sizeof(child));

        free(tag); free(newroot); free(oldroot);
        for(int i=0;i<argc;i++) free(argv[i]);
        close(client);
    }
}
// ---------- spawn_common ----------
static int file_exists(const char *path) {
    struct stat st; 
    return (stat(path,&st)==0 && S_ISREG(st.st_mode));
}

#include <dirent.h>

static void list_dir_recursive(const char *path) {
    int cnt = 20;
    DIR *d = opendir(path);
    if (!d) {
        LOG("cannot open %s: %s", path, strerror(errno));
        return;
    }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        char fullpath[PATH_MAX];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, de->d_name);
        LOG("ramdisk file: %s", fullpath);
#if 0
        if (de->d_type == DT_DIR) {
            list_dir_recursive(fullpath);
        }
#endif
        
        if (cnt-- < 0) break;
        sleep(1);
    }
    closedir(d);
}

pid_t spawn_common(int mode,const char *newroot,const char *oldroot,char **argv){
    LOG("%s enter", __func__);

    pid_t pid=fork();
    if(pid<0) return -1;
    if(pid==0){
        set_log_prefix("child");
        switch(mode){
            case MODE_PROXY:
                if(unshare(CLONE_NEWNS)<0)
        return -2;
                if(mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)<0) return -3;
                setup_filesystems(0);
                setup_console();
                proxy_loop(); 
                exit(0);
            case MODE_NS_SU:
                LOG("%s %s", __func__, argv[0]);
                if(argv && argv[0] && !file_exists(argv[0])) {
                        //return -ENOENT;
                        LOG("%s file NOT exist", __func__);
                    } else
                        LOG("%s file exist", __func__);

                execvp(argv[0],argv); 
                return -4;
            case MODE_NS_CHROOT_DEVTMPFS:
                LOG("%s %s", __func__, argv[0]);
                // Setup filesystem here.
                 if(unshare(CLONE_NEWPID)<0) return -2;
                LOG("%s %s after unshare", __func__, argv[0]);
#if 0
                 // Intented to let Android mount share to proxy server.
                //if(mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)<0) return -3;
#endif
                LOG("%s %s after mount private", __func__, argv[0]);
                setup_filesystems(1);
                setup_console();
LOG("%s %s after mount private", __func__, argv[0]);
                // Don't know why argv shift by 1. So align to argv[1]
                if(argv && argv[1] && !file_exists(argv[1])) {
                        //return -ENOENT;
                        LOG("%s file NOT exist %s %s %s", __func__, argv[0], argv[1], argv [2]);
#if 0
LOG("Listing ramdisk contents...");
list_dir_recursive("/");
LOG("Finished listing ramdisk contents");
#endif
                        sleep(30);
                        _exit(-1);
                    } else
                        LOG("%s file exist", __func__);
                execvp(argv[1],argv); 
                return -5;
            case MODE_NS_CHROOT:
                LOG("%s %s", __func__, argv[0]);

                if(chdir(newroot)<0) return -8;
                if(chroot(newroot)<0) return -9;
                if(argv && argv[0] && !file_exists(argv[0])) {
                        //return -ENOENT;
                        LOG("%s file NOT exist", __func__);
                        return -10;
                    } else
                        LOG("%s file exist", __func__);
                execvp(argv[0],argv); 
                return -5;
            default:
                return -6;
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
        close(sock); 
        return -1;
    }

    // Send TLVs
    send_tlv(sock, TLV_TAG, tag);
    if (newroot) send_tlv(sock, TLV_NEWROOT, newroot);
    if (oldroot) send_tlv(sock, TLV_OLDROOT, oldroot);
    for (int i = 0; i < argc; i++) send_tlv(sock, TLV_ARG, argv[i]);

    // End marker
    send_tlv(sock, TLV_END, "");

    pid_t child=-1;
    if(read_all(sock,&child,sizeof(child))!=sizeof(child)) child=-1;
    close(sock);
    return child;
}

int main_ns_chroot_android(int argc, char *argv[]);

#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

static int resolve_path(const char *candidate, char *out, size_t outlen) {
    struct stat st;
    if (lstat(candidate, &st) != 0) return 0; // not found

    strncpy(out, candidate, outlen - 1);
    out[outlen - 1] = '\0';

    if (S_ISLNK(st.st_mode)) {
        char linkbuf[PATH_MAX];
        ssize_t len = readlink(candidate, linkbuf, sizeof(linkbuf)-1);
        if (len > 0) {
            linkbuf[len] = '\0';
            LOG("%s is symlink -> %s", candidate, linkbuf);
            strncpy(out, linkbuf, outlen - 1);
            out[outlen - 1] = '\0';
        }
    }
    return 1;
}
static int parse_cmdline_init(char *out, size_t outlen) {
    FILE *f = fopen("/proc/cmdline", "r");
    if (!f) { LOG("cannot open /proc/cmdline: %s", strerror(errno)); return -1; }

    char buf[4096];
    if (!fgets(buf, sizeof(buf), f)) { LOG("failed to read /proc/cmdline"); fclose(f); return -1; }
    fclose(f);

    // Look for " init=" or start "init="
    char *p = strstr(buf, " init=");
    if (!p && strncmp(buf, "init=", 5) == 0) p = buf;
    if (p) {
        if (p[0] == ' ') p++; // skip space
        p += 5; // skip "init="
        char candidate[PATH_MAX];
        size_t i = 0;
        while (*p && *p != ' ' && i < sizeof(candidate) - 1) {
            candidate[i++] = *p++;
        }
        candidate[i] = '\0';
        if (resolve_path(candidate, out, outlen)) {
            LOG("cmdline init= resolved: %s", out);
            return 1;
        }
    }

    // Fallbacks
    const char *fallbacks[] = {
        "/init",
        "/system/bin/init",
        "/sbin/init",
        "/etc/init",
        "/bin/init",
        "/bin/sh"
    };
    for (int i = 0; i < (int)(sizeof(fallbacks)/sizeof(fallbacks[0])); i++) {
        if (resolve_path(fallbacks[i], out, outlen)) {
            LOG("no init=, fallback to %s", out);
            return 2;
        }
    }

    LOG("no init found, nothing to exec");
    return 0;
}

// ---------- main_rdinit ----------
int main_rdinit(int argc, char **argv) {
    set_log_prefix("rdinit");
    LOG("rdinit proxy starting...");

    if (unshare(CLONE_NEWNS) < 0) { perror("unshare(CLONE_NEWNS)"); return 1; }
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) { perror("make-rprivate"); return 1; }
    setup_filesystems(0);
    setup_console();
    pid_t proxy = spawn_common(MODE_PROXY, NULL, NULL, NULL);
    if (proxy < 0) { fprintf(stderr, "spawn proxy failed\n"); return 1; }
    signal(SIGCHLD, sigchld_handler);

    // If debug mode is enabled, stop here (proxy only)
    if (debug_mode) {
        LOG("Debug mode active: proxy spawned, skipping container creation");
        return 0;
    }

LOG("check if console is fine");

    // Otherwise, delegate to ns-chroot to create default container
    char *child_argv[MAX_ARGS]; int n = 0;

    char init_path[256];
int ret = parse_cmdline_init(init_path, sizeof(init_path));
if (ret > 0) {
    // Found init=, init_path contains the value
    LOG("Using init override: %s", init_path);
} else {
    // No init=, fall back to default /init
    LOG("No init override, using default /init");
}

    if (argc > 1) {
        for (int i = 1; i < argc && n < MAX_ARGS - 1; i++)
            child_argv[n++] = argv[i];
        child_argv[n++] = NULL;
    } else {
        // This is the default init path
        child_argv[++n] = "ns-chroot";
        child_argv[++n] = "./";
        child_argv[++n] = init_path; 
        child_argv[++n] = "NULL";
    }
    

    // Call into ns-chroot submain to run /init inside container
    int cnt = 10;
    while (cnt-- > 0) {
        int ret = main_ns_chroot_android
(n, child_argv);
        if (ret) {
            sleep(1);
            continue;
        } else {
            break;
        }
    }
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {}
    sleep(150);
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
int main_ns_chroot_ex(int argc, char *argv[], int mode) {
    set_log_prefix("ns-chroot");

    for (int i = 1; i < argc; i++) {
        LOG("%s", argv[i]);
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

    pid_t child = sock_send_request(mode?"NS_CHROOT":"NS_CHROOT_DEVTMPFS", argv[1], "oldroot", child_argv, n);
    if (child < 0) { fprintf(stderr, "ns-chroot failed\n"); return 1; }

    printf("Proxy spawned ns-chroot pid=%d\n", child);
    return 0;
}

int main_ns_chroot(int argc, char *argv[]) {
    return main_ns_chroot_ex(argc, argv, 1);
}

int main_ns_chroot_android(int argc, char *argv[]) {
    LOG("%s", __func__);
    return main_ns_chroot_ex(argc, argv, 0);
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
    } else if (strcmp(execname, "ns-chroot-android") == 0) {
        return main_ns_chroot_android(argc, argv);
    } else {
        set_log_prefix("unknown");
        LOG("unknown invocation %s", execname);
        fprintf(stderr, "Supported subcommands: rdinit, ns-su, ns-chroot\n");
        return 1;
    }
}
