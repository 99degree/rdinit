#define _GNU_SOURCE
#include <arpa/inet.h>      /* htons/ntohs */
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/un.h>
// Forward declaration
static pid_t send_proxy_request(const char *tag,
                           const char *newroot,
                           const char *oldroot,
                           char **argv,
                           int argc,
                           const char *tty_path);

#include <sys/wait.h>
#include <unistd.h>

/*=======================================================================
 * rdinit.c - single-file init / proxy implementation
 *
 *   * Compiles to one binary (or several symlinks: rdinit, ns-su,
 *     ns-chroot, ...) - behaviour is selected at run-time based on argv[0]
 *     or the first non-option argument, exactly as before.
 *
 *   * All "heavy" logic lives in static helpers - this makes unit-testing
 *     straightforward while keeping the final executable < 80 KB (no
 *     extra object files, no dynamic libraries required).
 *=======================================================================*/

/*-----------------------------------------------------------------------
 *  Configuration
 *-----------------------------------------------------------------------*/
#ifndef INIT_FALLBACKS
/* Default fallback list - can be overridden at compile time:
 *   gcc -DINIT_FALLBACKS='"/custom/init:/init"' ...
 */
#define INIT_FALLBACKS "/init:/system/bin/init:/sbin/init:/bin/init:/bin/sh"
#endif

#define ABSTRACT_SOCK_NAME "nssu_abstract_v1"
#define MAX_ARGS            64
#define MAX_TLV_PAYLOAD    1024   /* safe upper bound for a single TLV value */

/*-----------------------------------------------------------------------
 *  TLV definitions (type, length, value)
 *-----------------------------------------------------------------------*/
enum {
    TLV_TAG      = 0x01,
    TLV_ARG      = 0x02,
    TLV_NEWROOT  = 0x03,
    TLV_OLDROOT  = 0x04,
    TLV_TTY      = 0x05,
    TLV_END      = 0xFF
};

/*-----------------------------------------------------------------------
 *  Logging helpers (stderr + optional /dev/kmsg)
 *-----------------------------------------------------------------------*/
static int  kmsg_fd   = -1;
static bool log_enable = true;
static bool debug_mode = false;
#ifdef __ANDROID__
static const char *log_prefix = "rdinit";  /* Android TLS alignment workaround */
#else
static __thread const char *log_prefix = "rdinit";
#endif
static volatile sig_atomic_t child_exited = 0;

static void sigchld_handler(int sig) { (void)sig; child_exited = 1; }

static void set_log_prefix(const char *p) { log_prefix = p; }

static void setup_signal_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
}

static void log_msg(const char *fmt, ...)
{
    if (!log_enable) return;

    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[%s] ", log_prefix);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);

    if (kmsg_fd >= 0) {
        char buf[256];
        va_start(ap, fmt);
        int len = vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        if (len > 0) {
            dprintf(kmsg_fd, "<6>[%s] %s\n", log_prefix, buf);
        }
    }
}
#define LOG(...)   log_msg(__VA_ARGS__)
#define LOG_ERR(...)  log_msg(__VA_ARGS__)

/*-----------------------------------------------------------------------
 *  Small wrappers that abort on fatal error (used during init)
 *-----------------------------------------------------------------------*/
static void abort_msg(const char *msg)
{
    LOG_ERR("%s", msg);
    _exit(1);
}

/*-----------------------------------------------------------------------
 *  File-system helpers
 *-----------------------------------------------------------------------*/
static bool file_is_executable(const char *path)
{
    struct stat st;
    if (stat(path, &st) < 0) return false;
    return S_ISREG(st.st_mode) && (access(path, X_OK) == 0);
}

/* Resolve a path, follow a single symlink, and verify it is executable. */
static bool resolve_executable(const char *candidate, char *out, size_t outlen)
{
    struct stat st;
    if (lstat(candidate, &st) != 0) return false;

    /* If it is a symlink, follow it once - the original code only did that. */
    if (S_ISLNK(st.st_mode)) {
        char linkbuf[PATH_MAX];
        ssize_t len = readlink(candidate, linkbuf, sizeof(linkbuf) - 1);
        if (len <= 0) return false;
        linkbuf[len] = '\0';
        strncpy(out, linkbuf, outlen - 1);
        out[outlen - 1] = '\0';
    } else {
        strncpy(out, candidate, outlen - 1);
        out[outlen - 1] = '\0';
    }

    return file_is_executable(out);
}

/*-----------------------------------------------------------------------
 *  Kernel command-line parsing + init-path discovery
 *-----------------------------------------------------------------------*/
static bool parse_cmdline_init(char *out, size_t outlen)
{
    FILE *f = fopen("/proc/cmdline", "r");
    if (!f) {
        LOG_ERR("cannot open /proc/cmdline: %s", strerror(errno));
        return false;
    }

    char buf[4096];
    if (!fgets(buf, sizeof(buf), f)) {
        LOG_ERR("failed to read /proc/cmdline");
        fclose(f);
        return false;
    }
    fclose(f);

    /* Look for "init=" - it may appear as the first token or after a space */
    char *p = strstr(buf, " init=");
    if (!p && strncmp(buf, "init=", 5) == 0)
        p = buf;

    if (p) {
        p += (*p == ' ') ? 7 : 5;   /* skip the leading space and "init=" */
        char candidate[PATH_MAX];
        size_t i = 0;
        while (*p && *p != ' ' && i < sizeof(candidate) - 1)
            candidate[i++] = *p++;
        candidate[i] = '\0';

        if (resolve_executable(candidate, out, outlen)) {
            LOG("cmdline init= resolved to %s", out);
            return true;
        }
        LOG_ERR("init= %s not executable", candidate);
    }

    return false;
}

/* Split a colon-separated list in the environment variable or in the macro. */
static const char *fallback_list(void)
{
    const char *env = getenv("RDINIT_FALLBACKS");
    return env ? env : INIT_FALLBACKS;
}

/* Return a newly malloc'ed string containing the first valid init binary,
 * or NULL on failure (errno set to ENOENT). */
static char *find_init_path(const char *override)
{
    char path[PATH_MAX];

    /* 1) explicit override (e.g. from the kernel cmdline) */
    if (override && resolve_executable(override, path, sizeof(path)))
        return strdup(path);

    /* 2) try the cmdline "init=" first */
    if (parse_cmdline_init(path, sizeof(path)))
        return strdup(path);

    /* 3) walk the fallback list */
    const char *list = fallback_list();
    char *dup = strdup(list);
    if (!dup) return NULL;

    char *saveptr = NULL;
    char *token = strtok_r(dup, ":", &saveptr);
    while (token) {
        if (resolve_executable(token, path, sizeof(path))) {
            free(dup);
            return strdup(path);
        }
        token = strtok_r(NULL, ":", &saveptr);
    }
    free(dup);
    errno = ENOENT;
    return NULL;
}

/*-----------------------------------------------------------------------
 *  TLV read / write helpers (endian-safe, handles short reads/writes)
 *-----------------------------------------------------------------------*/
static ssize_t write_all(int fd, const void *buf, size_t count)
{
    const uint8_t *p = buf;
    size_t left = count;
    while (left) {
        ssize_t w = write(fd, p, left);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        left -= (size_t)w;
        p += w;
    }
    return (ssize_t)count;
}

/* Read exactly @count bytes - return <0 on error, 0 on EOF, >0 on success */
static ssize_t read_all(int fd, void *buf, size_t count)
{
    uint8_t *p = buf;
    size_t left = count;
    while (left) {
        ssize_t r = read(fd, p, left);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return 0;          /* EOF before we got all bytes */
        left -= (size_t)r;
        p   += r;
    }
    return (ssize_t)count;
}

/* Send a single TLV (type:uint8, len:uint16 network order, payload). */
static int tlv_send(int fd, uint8_t type, const char *val)
{
    uint16_t len = (uint16_t)strlen(val);
    uint16_t netlen = htons(len);
    if (write_all(fd, &type, 1)   < 0) return -1;
    if (write_all(fd, &netlen, 2) < 0) return -1;
    if (len && write_all(fd, val, len) < 0) return -1;
    return 0;
}

/* Receive a single TLV. Returns malloc'ed payload (caller must free).
 * On error returns NULL and optionally stores the type in @out_type.   */
static char *tlv_recv(int fd, uint8_t *out_type)
{
    uint8_t type;
    uint16_t netlen, len;

    if (read_all(fd, &type,   1) != 1) return NULL;
    if (read_all(fd, &netlen, 2) != 2) return NULL;
    len = ntohs(netlen);

    if (len > MAX_TLV_PAYLOAD) {   /* defensive guard */
        LOG_ERR("TLV payload too large (%u bytes)", len);
        /* Drain the oversized payload so the stream stays in sync */
        char tmp[256];
        size_t to_read = len;
        while (to_read) {
            size_t chunk = to_read > sizeof(tmp) ? sizeof(tmp) : to_read;
            if (read_all(fd, tmp, chunk) != (ssize_t)chunk) break;
            to_read -= chunk;
        }
        errno = EINVAL;
        return NULL;
    }

    char *buf = malloc(len + 1);
    if (!buf) return NULL;
    if (len && read_all(fd, buf, len) != (ssize_t)len) {
        free(buf);
        return NULL;
    }
    buf[len] = '\0';
    if (out_type) *out_type = type;
    return buf;
}

/* Validate TLV tag - returns true if valid */
static bool tlv_tag_valid(const char *tag)
{
    if (!tag) return false;
    const char *valid[] = {"NS_SU", "NS_CHROOT", "NS_CHROOT_DEVTMPFS", "PROXY", NULL};
    for (int i = 0; valid[i]; i++)
        if (strcmp(tag, valid[i]) == 0) return true;
    return false;
}

/*-----------------------------------------------------------------------
 *  Proxy - accepts TLV streams and runs the requested command
 *-----------------------------------------------------------------------*/
enum {
    MODE_PROXY               = 1,
    MODE_NS_SU               = 2,
    MODE_NS_CHROOT           = 3,
    MODE_NS_CHROOT_DEVTMPFS  = 4
};

/* Forward declaration - defined later */
static pid_t spawn_common(int mode,
                          const char *newroot,
                          const char *oldroot,
                          char **argv, const char *tty_path);

/* -------------------------------------------------------------
 *  proxy_loop()
 *
 *  Listens on an abstract unix socket, receives a single TLV
 *  request, dispatches to spawn_common(), and returns the child
 *  PID to the client.
 * ------------------------------------------------------------- */
static void proxy_loop(void)
{
    set_log_prefix("proxy");
    LOG("starting proxy loop");

    int listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0)
        abort_msg("socket() failed");

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    size_t n = strlen(ABSTRACT_SOCK_NAME);
    addr.sun_path[0] = '\0';
    memcpy(&addr.sun_path[1], ABSTRACT_SOCK_NAME, n);
    socklen_t addrlen = offsetof(struct sockaddr_un, sun_path) + 1 + n;

    /* Retry bind with exponential backoff */
    int bind_retries = 5;
    while (bind_retries--) {
        if (bind(listen_fd, (struct sockaddr *)&addr, addrlen) == 0)
            break;
        if (bind_retries == 0) {
            abort_msg("bind() failed");
        }
        LOG("bind() failed, retrying in 2 seconds...");
        sleep(2);
    }

    if (listen(listen_fd, 5) < 0)
\n    // Auto-spawn init if running as PID 1
    if (getpid() == 1) {
        LOG("Running as PID 1, auto-spawning init");
        char *init_path = find_init_path(NULL);
        if (init_path) {
            LOG("Found init: %s", init_path);
            
            char *argv[4] = {"ns-chroot", "./", init_path, NULL};
            const char *tty = ttyname(STDOUT_FILENO);
            if (!tty) tty = "/dev/tty";
            
            pid_t init_pid = spawn_common(MODE_NS_CHROOT, "./", NULL, &argv[2], tty);
            if (init_pid > 0) {
                LOG("Successfully spawned init (pid %d)", init_pid);
            } else {
                LOG_ERR("Failed to spawn init");
            }
            free(init_path);
        }
    }
        abort_msg("listen() failed");

        int client = accept(listen_fd, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue;
            LOG_ERR("accept() failed: %s", strerror(errno));
            continue;
        }

        /* ----------------------------------------------------------------
         *  Parse the incoming TLV stream.
         *  The protocol is tiny, so we keep everything on the stack.
         * ---------------------------------------------------------------- */
        char *tag = NULL, *newroot = NULL, *oldroot = NULL, *tty_path = NULL;
        char *argv[MAX_ARGS];
        int   argc = 0;
        bool  end_seen = false;

        while (!end_seen) {
            uint8_t type;
            char *val = tlv_recv(client, &type);
            if (!val) break;   /* malformed or EOF */

            switch (type) {
            case TLV_TAG:    tag = val;    break;
            case TLV_NEWROOT:newroot = val;break;
            case TLV_OLDROOT:oldroot = val;break;
            case TLV_TTY: tty_path = val; break;
            case TLV_ARG:
                if (argc < MAX_ARGS - 1) argv[argc++] = val;
                else { free(val); LOG_ERR("too many arguments"); }
                break;
            case TLV_END:
                end_seen = true;
                free(val);
                break;
            default:
                LOG_ERR("unknown TLV type %u - ignoring", type);
                free(val);
                break;
            }
        }
        argv[argc] = NULL;   /* ensure NULL termination */

        /* ------------------------------------------------------------
         *  Resolve mode from the tag.
         * ------------------------------------------------------------ */
        int mode = -1;
        if (tag && tlv_tag_valid(tag)) {
            if (strcmp(tag, "NS_SU")                == 0) mode = MODE_NS_SU;
            else if (strcmp(tag, "NS_CHROOT")       == 0) mode = MODE_NS_CHROOT;
            else if (strcmp(tag, "NS_CHROOT_DEVTMPFS") == 0) mode = MODE_NS_CHROOT_DEVTMPFS;
            else if (strcmp(tag, "PROXY")          == 0) mode = MODE_PROXY;
        }

        pid_t child = -1;
        if (mode > 0) {
            child = spawn_common(mode, newroot, oldroot, argv, tty_path);
            LOG("spawn_common returned pid %d (mode=%d)", child, mode);
        } else {
            LOG_ERR("invalid or missing TAG TLV: %s", tag ? tag : "(null)");
        }

        /* Return the child-PID (or -1) to the client */
        if (write_all(client, &child, sizeof(child)) < 0)
            LOG_ERR("failed to send child PID to client");

        /* Clean up */
        free(tag);
        free(newroot);
        free(oldroot);
        for (int i = 0; i < argc; ++i) free(argv[i]);
        close(client);
    }
}

/*-----------------------------------------------------------------------
 *  Namespace / filesystem bootstrap
 *-----------------------------------------------------------------------*/
static void mount_proc(void)
{
 struct stat st;

 /* Ensure /proc directory exists */
 if (stat("/proc", &st) != 0) {
  if (mkdir("/proc", 0555) < 0 && errno != EEXIST) {
   LOG_ERR("mkdir /proc failed: %s", strerror(errno));
   return;
  }
 }

 /* Mount /proc */
 if (mount("proc", "/proc", "proc", MS_NOEXEC|MS_NOSUID|MS_NODEV, NULL) < 0)
  LOG_ERR("mount /proc failed: %s", strerror(errno));
 else
  LOG("mounted /proc");
}

/* Create a tiny /dev (tmpfs) and the essential character devices. */
static void mount_dev(bool use_devtmpfs)
{
    struct stat st;

    /* Ensure /proc directory exists */
    if (stat("/proc", &st) != 0) {
      if (mkdir("/proc", 0555) < 0 && errno != EEXIST) {
          LOG_ERR("mkdir /proc failed: %s", strerror(errno));
          return;
      }
    }

    if (debug_mode) {
        LOG("mount_dev: skipping in debug mode");
    } else if (use_devtmpfs) {
        if (mount("devtmpfs", "/dev", "devtmpfs", 0, "mode=0755") < 0)
            LOG_ERR("mount devtmpfs failed: %s", strerror(errno));
    } else {
        if (mount("tmpfs", "/dev", "tmpfs", 0, "mode=0755,size=64M") < 0)
            LOG_ERR("mount tmpfs on /dev failed: %s", strerror(errno));
    }

    /* Minimal device nodes - errors are non-fatal */
    mknod("/dev/null",    S_IFCHR|0666, makedev(1, 3));
    mknod("/dev/zero",    S_IFCHR|0666, makedev(1, 5));
    mknod("/dev/full",    S_IFCHR|0666, makedev(1, 7));
    mknod("/dev/random",  S_IFCHR|0666, makedev(1, 8));
    mknod("/dev/urandom", S_IFCHR|0666, makedev(1, 9));
    mknod("/dev/tty",     S_IFCHR|0666, makedev(5, 0));
    mknod("/dev/console", S_IFCHR|0600, makedev(5, 1));
    mknod("/dev/kmsg",    S_IFCHR|0644, makedev(1, 11));
}

/* Perform the common mount-namespace setup (called by both init and proxy). */
static void setup_mount_namespace(void) {
 if (debug_mode) {
  LOG("setup_mount_namespace: skipping in debug mode");
  return;
 }

 /* Create PID namespace FIRST to avoid EINVAL issues with mount namespace */
 if (unshare(CLONE_NEWPID | CLONE_NEWNS) < 0) {
  LOG_ERR("unshare(CLONE_NEWPID) failed: %s", strerror(errno));
 } else {
  LOG("unshared PID/MOUNT namespace - now running as PID %d inside", getpid());
 }

 if (mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL) < 0) {
  LOG_ERR("remount / private failed: %s", strerror(errno));
 } else {
  LOG("remounted / as private");
 }

 /* Ensure essential directories exist */
 struct stat st;
 if (stat("/dev", &st) != 0) {
  if (mkdir("/dev", 0755) < 0 && errno != EEXIST)
   LOG_ERR("mkdir /dev failed: %s", strerror(errno));
 }
 if (stat("/proc", &st) != 0) {
  if (mkdir("/proc", 0755) < 0 && errno != EEXIST)
   LOG_ERR("mkdir /proc failed: %s", strerror(errno));
 }
 if (stat("/sys", &st) != 0) {
  if (mkdir("/sys", 0755) < 0 && errno != EEXIST)
   LOG_ERR("mkdir /sys failed: %s", strerror(errno));
 }

 mount_proc();
}

/*-----------------------------------------------------------------------
 *  Console / kmsg redirection
 *-----------------------------------------------------------------------*/
static void redirect_to_kmsg(void)
{
    int fd = open("/dev/kmsg", O_WRONLY|O_CLOEXEC);
    if (fd < 0) {
        LOG_ERR("cannot open /dev/kmsg: %s", strerror(errno));
        return;
    }

    if (!debug_mode) {
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
    }
    kmsg_fd = fd;
}

/*-----------------------------------------------------------------------
 *  spawn_common()
 *
 *  Forks and runs the requested mode:
 *      MODE_PROXY               - become a new proxy (used by the init).
 *      MODE_NS_SU               - exec the supplied binary directly.
 *      MODE_NS_CHROOT           - chroot to newroot then exec.
 *      MODE_NS_CHROOT_DEVTMPFS  - PID-namespace + fresh /dev tmpfs.
 *-----------------------------------------------------------------------*/
static pid_t spawn_common(int mode,
                          const char *newroot,
                          const char *oldroot,  /* reserved for future use */
                          char **argv,
                          const char *tty_path)
{
    (void)oldroot;  /* currently unused, reserved for future use */
    pid_t pid = fork();
    if (pid < 0) {
        LOG_ERR("fork() failed: %s", strerror(errno));
        return -1;
    }
    if (pid == 0) {          /* child */
        /* Close everything that the parent kept open (listener, kmsg, etc.).
         * We keep stdin/stdout/stderr because the proxy may redirect them. */
        long fd_limit = sysconf(_SC_OPEN_MAX);
        if (fd_limit < 0 || fd_limit > 1024) fd_limit = 1024;
        for (int fd = 3; fd < fd_limit; ++fd) close(fd);

        switch (mode) {
        case MODE_PROXY:
            LOG("child entering proxy mode");
            setup_mount_namespace();
            mount_dev(false);
            redirect_to_kmsg();

            proxy_loop();          /* never returns */
            _exit(0);

        case MODE_NS_SU: {
            if (tty_path && tty_path[0]) {
                int tty_fd = open(tty_path, O_RDWR);
                if (tty_fd >= 0) {
                    dup2(tty_fd, STDIN_FILENO);
                    dup2(tty_fd, STDOUT_FILENO);
                    dup2(tty_fd, STDERR_FILENO);
                    close(tty_fd);
                }
            }
            LOG("child executing %s (su mode)", argv[0] ? argv[0] : "(null)");
            execvp(argv[0], argv);
            LOG_ERR("execvp %s failed: %s", argv[0], strerror(errno));
            _exit(127);
        }

        case MODE_NS_CHROOT: {
            if (tty_path && tty_path[0]) {
                int tty_fd = open(tty_path, O_RDWR);
                if (tty_fd >= 0) {
                    dup2(tty_fd, STDIN_FILENO);
                    dup2(tty_fd, STDOUT_FILENO);
                    dup2(tty_fd, STDERR_FILENO);
                    close(tty_fd);
                }
            }
            LOG("child chroot to %s", newroot);
            if (chdir(newroot) < 0) {
                LOG_ERR("chdir(%s) failed: %s", newroot, strerror(errno));
                _exit(1);
            }
            if (chroot(newroot) < 0) {
                LOG_ERR("chroot(%s) failed: %s", newroot, strerror(errno));
                _exit(1);
            }
            execvp(argv[0], argv);
            LOG_ERR("execvp %s failed: %s", argv[0], strerror(errno));
            _exit(127);
        }

        case MODE_NS_CHROOT_DEVTMPFS:
            LOG("child entering chroot+devtmpfs mode");
            if (unshare(CLONE_NEWPID) < 0) {
                LOG_ERR("unshare(CLONE_NEWPID) failed: %s", strerror(errno));
                _exit(1);
            } if (!debug_mode) setup_mount_namespace(); else LOG("Skipping setup_mount_namespace in debug mode");
            mount_dev(true);      /* devtmpfs this time */
            if (!argv[1]) {
                LOG_ERR("no binary supplied for chroot-devtmpfs mode");
                _exit(1);
            }
            execvp(argv[1], &argv[1]);
            LOG_ERR("execvp %s failed: %s", argv[1], strerror(errno));
            _exit(127);
        }
        _exit(1);   /* should never reach here */
    }
    /* parent */
    return pid;
}

/*-----------------------------------------------------------------------
 *  Client helpers - send a request to the proxy and obtain the child PID
 *-----------------------------------------------------------------------*/
static pid_t send_proxy_request(const char *tag,
                                const char *newroot,
                                const char *oldroot,
                                char **argv,
                                int argc,
    const char *tty_path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG_ERR("socket() failed: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    size_t n = strlen(ABSTRACT_SOCK_NAME);
    addr.sun_path[0] = '\0';
    memcpy(&addr.sun_path[1], ABSTRACT_SOCK_NAME, n);
    socklen_t addrlen = offsetof(struct sockaddr_un, sun_path) + 1 + n;

    /* Retry connect with exponential backoff */
    int connect_retries = 5;
    while (connect_retries--) {
        if (connect(fd, (struct sockaddr *)&addr, addrlen) == 0)
            break;
        if (connect_retries == 0) {
            LOG_ERR("connect() to proxy failed: %s", strerror(errno));
            close(fd);
            return -1;
        }
        LOG("connect() failed, retrying in 2 seconds...");
        sleep(2);
    }

    if (tlv_send(fd, TLV_TAG, tag) < 0)       goto fail;
    if (newroot && tlv_send(fd, TLV_NEWROOT, newroot) < 0) goto fail;
    if (oldroot && tlv_send(fd, TLV_OLDROOT, oldroot) < 0) goto fail;
    for (int i = 0; i < argc; ++i)
        if (tlv_send(fd, TLV_ARG, argv[i]) < 0) goto fail;
    if (tlv_send(fd, TLV_END, "") < 0)        goto fail;

    pid_t child = -1;
    if (read_all(fd, &child, sizeof(child)) != sizeof(child))
        child = -1;

    close(fd);
    return child;

fail:
    LOG_ERR("failed to send TLV request to proxy");
    close(fd);
    return -1;
}

/*-----------------------------------------------------------------------
 *  Subcommand entry points (ns-su, ns-chroot, ...)
 *-----------------------------------------------------------------------*/
static int cmd_ns_su(int argc, char *argv[])
{
    set_log_prefix("ns-su");
    if (argc < 2) {
        fprintf(stderr, "Usage: ns-su <binary> [args...]\n");
        return 1;
    }
    char *child_argv[MAX_ARGS];
    int  n = 0;
    for (int i = 1; i < argc && n < MAX_ARGS - 1; ++i)
        child_argv[n++] = argv[i];
    child_argv[n] = NULL;

    const char *tty_path = ttyname(STDOUT_FILENO);
 if (!tty_path) tty_path = "/dev/tty";
 pid_t child = send_proxy_request("NS_SU", NULL, NULL, child_argv, n, tty_path);
    if (child < 0) {
        fprintf(stderr, "ns-su failed\n");
        return 1;
    }
    printf("ns-su spawned pid %d\n", child);
    return 0;
}

static int cmd_ns_chroot(int argc, char *argv[], bool use_devtmpfs)
{
    set_log_prefix(use_devtmpfs ? "ns-chroot-devtmpfs" : "ns-chroot");
    if (argc < 4) {
        fprintf(stderr,
                "Usage: %s <root> <binary> [args...]\n", argv[0]);
        return 1;
    }
    const char *root = argv[2];

    char *child_argv[MAX_ARGS];
    int  n = 0;
    for (int i = 3; i < argc && n < MAX_ARGS - 1; ++i)
        child_argv[n++] = argv[i];
    child_argv[n] = NULL;

    const char *tag = use_devtmpfs ? "NS_CHROOT_DEVTMPFS" : "NS_CHROOT";
    const char *tty_path2 = ttyname(STDOUT_FILENO);
    if (!tty_path2) tty_path2 = "/dev/tty";
    pid_t child = send_proxy_request(tag, root, "oldroot", child_argv, n, tty_path2);
    if (child < 0) {
        fprintf(stderr, "ns-chroot failed\n");
        return 1;
    }
    printf("%s spawned pid %d\n", tag, child);
    return 0;
}

/*-----------------------------------------------------------------------
 *  Main rdinit (PID 1) - creates the proxy, looks for an init binary,
 *  and finally hands control over to it via the proxy.
 *-----------------------------------------------------------------------*/
static int rdinit_main(void)
{
    set_log_prefix("rdinit");
 pid_t original_pid = getpid();
 LOG("starting (original PID %d)", original_pid);

    /* Minimal mount namespace + /dev, /proc */
 if (!debug_mode) {
  setup_mount_namespace();
  mount_dev(false);
  redirect_to_kmsg();
 } else {
  LOG("Skipping setup in debug mode");
 }

 /* Spawn the proxy that will later run the real init */
    pid_t proxy = spawn_common(MODE_PROXY, NULL, NULL, NULL, NULL);
    if (proxy < 0)
        abort_msg("failed to start proxy");

    LOG("proxy spawned (pid %d)", proxy);

    /* -----------------------------------------------------------------
     *  Find the init binary (respecting cmdline "init=" first, then fall-
     *  backs).  The helper returns a malloc'ed string that we must free.
     * ----------------------------------------------------------------- */
      if (original_pid == 1) {

  if (original_pid == 1) {
    /* Minimal supervisor loop */
    while (1) {
        int status;
        pid_t w = waitpid(proxy, &status, WNOHANG);

        if (w == proxy) {
            /* Proxy died */
            if (WIFEXITED(status))
                LOG("proxy exited with %d", WEXITSTATUS(status));
            else if (WIFSIGNALED(status))
                LOG("proxy killed by signal %d", WTERMSIG(status));

            LOG("Restarting proxy...");
            proxy = spawn_common(MODE_PROXY, NULL, NULL, NULL, NULL);
            if (proxy <= 0) {
                LOG_ERR("Failed to restart proxy");
                abort_msg("Cannot continue");
            }
            LOG("Proxy restarted (pid %d)", proxy);
        }
        else if (w == 0) {
            /* Proxy is running, sleep to conserve CPU */
            sleep(1);
        }
        else {
            /* Error case */
            if (errno != ECHILD && errno != EINTR) {
                LOG_ERR("waitpid() failed: %s", strerror(errno));
            }
        }
    }
  } else {
    LOG("Not running as PID 1. Waiting for external commands...");
      } else {
    LOG("Not running as original PID 1. Proxy started. Waiting for external commands...");
  }

  /* --------------------------------------------------------------
   * Reap children forever. Using wait() with signal handler.
   * -------------------------------------------------------------- *//* --------------------------------------------------------------
     *  Reap children forever.  Using wait() with signal handler.
     * -------------------------------------------------------------- */
    setup_signal_handlers();
    while (1) {
        int status;
        pid_t w = wait(&status);
        if (w > 0) {
            if (WIFEXITED(status))
                LOG("child %d exited with %d", w, WEXITSTATUS(status));
            else if (WIFSIGNALED(status))
                LOG("child %d killed by signal %d", w, WTERMSIG(status));
            child_exited = 0;
        } else if (w < 0) {
            if (errno == ECHILD) {
                /* No children - wait for signal */
                while (!child_exited) pause();
                child_exited = 0;
            } else if (errno != EINTR)
                LOG_ERR("wait() failed: %s", strerror(errno));
        }
    }
    return 0;   /* never reached */
}

/*-----------------------------------------------------------------------
 *  Dispatcher - decides which sub-command to run based on argv[0] or the
 *  first argument after "rdinit".
 *-----------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
    /* Global flags - they apply to every sub-command */
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--debug") == 0) {
            debug_mode = true;   /* force init behavior even when PID!=1 */
            log_enable = true;
        } else if (strcmp(argv[i], "--quiet") == 0) {
            log_enable = false;
        } else if (strcmp(argv[i], "--help") == 0) {
            printf(
                "Supported commands:\n"
                "  rdinit                - PID 1 init (creates proxy & runs /init)\n"
                "  ns-su   <bin> [args] - run a binary inside the proxy namespace\n"
                "  ns-spawn <bin> [args] - synonym for ns-su (direct spawn)\n"
                "  ns-sudo  <bin> [args] - synonym for ns-su (simulated sudo)\n"
                "  ns-chroot <root> <bin> [args] - chroot then exec\n"
                "  ns-chroot-android ...   - same as ns-chroot but with devtmpfs\n"
                "\nGlobal options: --debug, --quiet, --help\n");
            return 0;
        }
    }

    /* If --debug was passed, force init behavior regardless of PID */
    if (debug_mode) {
        LOG("debug mode: forcing rdinit_main even though pid=%d", getpid());
        return rdinit_main();
    }

    /* Determine the invoked name */
    const char *base = strrchr(argv[0], '/');
    base = base ? base + 1 : argv[0];

    /* -----------------------------------------------------------------
     *  Direct invocation (by binary name) - this is the path used when the
     *  binaries are symlinked to the same executable.
     * ----------------------------------------------------------------- */
    if (strcmp(base, "rdinit") == 0) {
        /* rdinit may be called as "rdinit ns-su ..." - handle that case. */
        if (argc > 1 && strcmp(argv[1], "ns-su") == 0)
            return cmd_ns_su(argc - 1, argv + 1);
        if (argc > 1 && strcmp(argv[1], "ns-spawn") == 0)
            return cmd_ns_su(argc - 1, argv + 1);  /* spawn = su */
        if (argc > 1 && strcmp(argv[1], "ns-sudo") == 0)
            return cmd_ns_su(argc - 1, argv + 1);  /* sudo = su (simulated) */
        if (argc > 1 && strcmp(argv[1], "ns-chroot") == 0)
            return cmd_ns_chroot(argc - 1, argv + 1, false);
        if (argc > 1 && strcmp(argv[1], "ns-chroot-android") == 0)
            return cmd_ns_chroot(argc - 1, argv + 1, true);
        return rdinit_main();
    }

    /* -----------------------------------------------------------------
     *  If the binary name itself is a sub-command, delegate accordingly.
     * ----------------------------------------------------------------- */
    if (strcmp(base, "ns-su") == 0)
        return cmd_ns_su(argc, argv);
    if (strcmp(base, "ns-spawn") == 0)
        return cmd_ns_su(argc, argv);   /* spawn behaves like su */
    if (strcmp(base, "ns-sudo") == 0)
        return cmd_ns_su(argc, argv);   /* sudo behaves like su */

    if (strcmp(base, "ns-chroot") == 0)
        return cmd_ns_chroot(argc, argv, false);

    if (strcmp(base, "ns-chroot-android") == 0)
        return cmd_ns_chroot(argc, argv, true);

    /* Unknown binary - fall back to a helpful message */
    LOG_ERR("unknown invocation: %s", base);
    fprintf(stderr, "Supported binaries: rdinit, ns-su, ns-spawn, ns-sudo, ns-chroot, ns-chroot-android\n");
    return 1;
}
