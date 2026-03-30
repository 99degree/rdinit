#define _GNU_SOURCE
#include <stdio.h>      // printf, fprintf, snprintf, FILE, fopen, fread
#include <stdlib.h>     // exit, malloc, free
#include <string.h>     // strtok, strcmp, strncmp, strerror
#include <unistd.h>     // fork, exec, dup2, sleep, close, getpid, mkdir
#include <sched.h>
#include <sys/types.h>  // pid_t, mode_t
#include <sys/wait.h>   // waitpid
#include <sys/socket.h> // socketpair
#include <sys/mount.h>  // mount
#include <sys/stat.h>   // mknod, mkdir, S_IFCHR
#include <fcntl.h>      // open, O_RDWR, O_CLOEXEC
#include <errno.h>      // errno
#include <sys/sysmacros.h> // makedev
#include <signal.h>     // signal, SIGCHLD
#include <arpa/inet.h>   // for htons(), htonl(), ntohs(), ntohl()
#include <sched.h>       // unshare()
#include <sys/mount.h>   // mount(), MS_PRIVATE, MS_REC
#include <sys/stat.h>    // mknod(), mkdir()
#include <sys/sysmacros.h> // makedev()
#include <errno.h>
#include <string.h>
#include <unistd.h>

// --- TLV definitions ---
struct tlv_header {
    uint16_t type;
    uint16_t length;
};

enum tlv_type {
    TLV_SPAWN   = 1,
    TLV_SUDO    = 2,
    TLV_CHROOT  = 3,
    TLV_ARG     = 4,
    TLV_EXT     = 5,
    TLV_RESULT  = 6,
    TLV_ERROR   = 7,
    TLV_TTY     = 8,   // carries tty path string
    TLV_END     = 255
};

// --- Simple logging macros ---
#define LOG_INFOF(fmt, ...)  fprintf(stderr, "[INFO] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERRORF(fmt, ...) fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)
// Build TLV sequence with args + dynamic tty
static size_t build_tlv_command(uint16_t cmd_type, int argc, char **argv,
                                char *buffer, size_t bufsize) {
    size_t offset = 0;

    // Command marker
    struct tlv_header th = { htons(cmd_type), htons(0) };
    memcpy(buffer+offset, &th, sizeof(th));
    offset += sizeof(th);

    // Add args
    for (int i = 0; i < argc; i++) {
        struct tlv_header ah = { htons(TLV_ARG), htons(strlen(argv[i])) };
        memcpy(buffer+offset, &ah, sizeof(ah));
        offset += sizeof(ah);
        memcpy(buffer+offset, argv[i], strlen(argv[i]));
        offset += strlen(argv[i]);
    }

    // Detect tty dynamically
    const char *tty_path = ttyname(STDIN_FILENO);
    if (tty_path) {
        struct tlv_header th_tty = { htons(TLV_TTY), htons(strlen(tty_path)) };
        memcpy(buffer+offset, &th_tty, sizeof(th_tty));
        offset += sizeof(th_tty);
        memcpy(buffer+offset, tty_path, strlen(tty_path));
        offset += strlen(tty_path);
    }

    // End marker
    struct tlv_header end = { htons(TLV_END), htons(0) };
    memcpy(buffer+offset, &end, sizeof(end));
    offset += sizeof(end);

    return offset;
}
int spawn_main(int argc, char **argv) {
    char buffer[1024];
    size_t len = build_tlv_command(TLV_SPAWN, argc, argv, buffer, sizeof(buffer));
    write(STDOUT_FILENO, buffer, len);
    return 0;
}

int sudo_main(int argc, char **argv) {
    char buffer[1024];
    size_t len = build_tlv_command(TLV_SUDO, argc, argv, buffer, sizeof(buffer));
    write(STDOUT_FILENO, buffer, len);
    return 0;
}

int chroot_main(int argc, char **argv) {
    char buffer[1024];
    size_t len = build_tlv_command(TLV_CHROOT, argc, argv, buffer, sizeof(buffer));
    write(STDOUT_FILENO, buffer, len);
    return 0;
}
static int validate_command(const char *cmd) {
    struct stat st;
    if (stat(cmd, &st) < 0) {
        LOG_ERRORF("Command %s not found: %s", cmd, strerror(errno));
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        LOG_ERRORF("Command %s is not a regular file", cmd);
        return -1;
    }
    if (access(cmd, X_OK) < 0) {
        LOG_ERRORF("Command %s is not executable", cmd);
        return -1;
    }
    return 0;
}
static void send_tlv(int fd, uint16_t type, const char *msg) {
    struct tlv_header th = { htons(type), htons(strlen(msg)) };
    write(fd, &th, sizeof(th));
    write(fd, msg, strlen(msg));
}
static void exec_with_output(char **argv, int fd_out, const char *tty_path) {
    if (!argv || !argv[0]) {
        send_tlv(fd_out, TLV_ERROR, "empty argv");
        return;
    }

    if (validate_command(argv[0]) < 0) {
        send_tlv(fd_out, TLV_ERROR, "command not found or not executable");
        return;
    }

    int pipe_out[2], pipe_err[2];
    pipe(pipe_out); pipe(pipe_err);

    pid_t pid = fork();
    if (pid == 0) {
        // Child
        if (tty_path && tty_path[0]) {
            int tty = open(tty_path, O_RDWR);
            if (tty >= 0) {
                dup2(tty, STDIN_FILENO);
                dup2(tty, STDOUT_FILENO);
                dup2(tty, STDERR_FILENO);
                close(tty);
                LOG_INFOF("Child attached to %s", tty_path);
            }
        } else {
            dup2(pipe_out[1], STDOUT_FILENO);
            dup2(pipe_err[1], STDERR_FILENO);
        }
        close(pipe_out[0]); close(pipe_out[1]);
        close(pipe_err[0]); close(pipe_err[1]);

        execvp(argv[0], argv);
        LOG_ERRORF("execvp failed: %s", strerror(errno));
        exit(127);
    }

    close(pipe_out[1]); close(pipe_err[1]);

    if (!(tty_path && tty_path[0])) {
        char buf[512]; ssize_t n;
        while ((n = read(pipe_out[0], buf, sizeof(buf)-1)) > 0) {
            buf[n] = '\0';
            send_tlv(fd_out, TLV_RESULT, buf);
        }
        while ((n = read(pipe_err[0], buf, sizeof(buf)-1)) > 0) {
            buf[n] = '\0';
            send_tlv(fd_out, TLV_ERROR, buf);
        }
    }

    int status;
    waitpid(pid, &status, 0);
    char codebuf[64];
    snprintf(codebuf, sizeof(codebuf), "exit=%d", WEXITSTATUS(status));
    send_tlv(fd_out, TLV_RESULT, codebuf);

    struct tlv_header end = { htons(TLV_END), htons(0) };
    write(fd_out, &end, sizeof(end));
}

static void proxy_loop(int fd_in, int fd_out) {
    while (1) {
        char buffer[4096];
        ssize_t n = read(fd_in, buffer, sizeof(buffer));
        if (n <= 0) {
            LOG_INFOF("proxy_loop: input closed, exiting");
            break;
        }

        size_t offset = 0;
        char *argv[32]; int argc = 0;
        int cmd_type = 0;
        char tty_path[128] = {0};

        // --- Parse TLVs ---
        while (offset + sizeof(struct tlv_header) <= (size_t)n) {
            struct tlv_header hdr;
            memcpy(&hdr, buffer + offset, sizeof(hdr));
            offset += sizeof(hdr);

            uint16_t type = ntohs(hdr.type);
            uint16_t len  = ntohs(hdr.length);

            if (type == TLV_END) break;
            if (offset + len > (size_t)n) break;

            char val[512];
            memcpy(val, buffer + offset, len);
            val[len] = '\0';
            offset += len;

            switch (type) {
            case TLV_SPAWN:
            case TLV_SUDO:
            case TLV_CHROOT:
                cmd_type = type;
                break;
            case TLV_ARG:
                if (argc < 31) argv[argc++] = strdup(val);
                break;
            case TLV_TTY:
                strncpy(tty_path, val, sizeof(tty_path)-1);
                LOG_INFOF("Proxy received TTY path: %s", tty_path);
                break;
            case TLV_EXT:
                LOG_INFOF("Proxy received EXT: %s", val);
                break;
            default:
                LOG_ERRORF("Unknown TLV type %u", type);
                break;
            }
        }
        argv[argc] = NULL;

        // --- Dispatch ---
        if (cmd_type == TLV_SPAWN) {
            LOG_INFOF("Proxy executing SPAWN");
            exec_with_output(argv, fd_out, tty_path);

        } else if (cmd_type == TLV_SUDO) {
            LOG_INFOF("Proxy executing SUDO");
            exec_with_output(argv, fd_out, tty_path);

        } else if (cmd_type == TLV_CHROOT) {
            LOG_INFOF("Proxy executing CHROOT");
            if (!argv[0]) {
                send_tlv(fd_out, TLV_ERROR, "chroot missing target");
            } else if (validate_command(argv[0]) < 0) {
                send_tlv(fd_out, TLV_ERROR, "chroot target invalid");
            } else if (chroot(argv[0]) < 0) {
                char errbuf[128];
                snprintf(errbuf, sizeof(errbuf), "chroot failed: %s", strerror(errno));
                send_tlv(fd_out, TLV_ERROR, errbuf);
            } else {
                exec_with_output(&argv[1], fd_out, tty_path);
            }

        } else {
            LOG_ERRORF("Proxy received unknown or missing command TLV");
            send_tlv(fd_out, TLV_ERROR, "unknown command");
        }

        // --- Cleanup argv ---
        for (int i = 0; i < argc; i++) {
            free(argv[i]);
        }
    }
}
static void print_help(const char *progname) {
    printf("Usage: %s [command] [args...]\n", progname);
    printf("\nCommands:\n");
    printf("  spawn   Run a command directly\n");
    printf("  sudo    Run a command with elevated privileges (simulated)\n");
    printf("  chroot  Run a command inside a new root directory\n");
    printf("\nOptions:\n");
    printf("  --help  Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s spawn /bin/echo hello\n", progname);
    printf("  %s sudo /bin/ls -l\n", progname);
    printf("  %s chroot /newroot /bin/bash\n", progname);
}

void setup_consoles_from_cmdline(void) {
    char cmdline[4096] = {0};
    FILE *f = fopen("/proc/cmdline", "r");
    if (!f) return;
    fread(cmdline, 1, sizeof(cmdline)-1, f);
    fclose(f);

    char *tok = strtok(cmdline, " ");
    const char *last_console = NULL;
    while (tok) {
        if (strncmp(tok, "console=", 8) == 0) {
            last_console = tok + 8;
            // optional: open each console here
            int fd = open(last_console, O_RDWR | O_CLOEXEC);
            if (fd >= 0) {
                // duplicate to stdout/stderr
                dup2(fd, STDOUT_FILENO);
                dup2(fd, STDERR_FILENO);
                // keep stdin too if desired
                dup2(fd, STDIN_FILENO);
                close(fd);
            }
        }
        tok = strtok(NULL, " ");
    }
    if (last_console) {
        LOG_INFOF("Bound init logs to console device: %s", last_console);
    }
}

static void setup_mounts_and_dev_unshare(void) {
    // Unshare mount namespace
    if (unshare(CLONE_NEWNS | CLONE_NEWPID) < 0) {
        LOG_ERRORF("unshare(CLONE_NEWNS | CLONE_NEWPID) failed: %s", strerror(errno));
    } else {
        LOG_INFOF("Unshared mount namespace");
    }
}
static void setup_mounts_and_dev(void) {
    setup_mounts_and_dev_unshare();
    // Make / private
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
        LOG_ERRORF("Remount / private failed: %s", strerror(errno));
    } else {
        LOG_INFOF("Remounted / as private");
    }

    // Ensure dirs
    mkdir("/dev", 0755);
    mkdir("/proc", 0755);
    mkdir("/sys", 0755);

    // Mount tmpfs on /dev
    if (mount("tmpfs", "/dev", "tmpfs", MS_NOSUID|MS_STRICTATIME, "size=1M") < 0)
        LOG_ERRORF("Mount /dev tmpfs failed: %s", strerror(errno));
    else
        LOG_INFOF("Mounted /dev as tmpfs");

    // Mount proc and sysfs
    if (mount("proc", "/proc", "proc", 0, "") < 0)
        LOG_ERRORF("Mount /proc failed: %s", strerror(errno));
    else
        LOG_INFOF("Mounted /proc");
#if 0
    if (mount("sysfs", "/sys", "sysfs", 0, "") < 0)
        LOG_ERRORF("Mount /sys failed: %s", strerror(errno));
    else
        LOG_INFOF("Mounted /sys");
#endif

    // Create essential device nodes
    if (mknod("/dev/null",    S_IFCHR | 0666, makedev(1, 3)) < 0)
        LOG_ERRORF("mknod /dev/null failed: %s", strerror(errno));
    if (mknod("/dev/zero",    S_IFCHR | 0666, makedev(1, 5)) < 0)
        LOG_ERRORF("mknod /dev/zero failed: %s", strerror(errno));
    if (mknod("/dev/console", S_IFCHR | 0600, makedev(5, 1)) < 0)
        LOG_ERRORF("mknod /dev/console failed: %s", strerror(errno));
    if (mknod("/dev/tty",     S_IFCHR | 0666, makedev(5, 0)) < 0)
        LOG_ERRORF("mknod /dev/tty failed: %s", strerror(errno));
    if (mknod("/dev/kmsg",    S_IFCHR | 0644, makedev(1, 11)) < 0)
        LOG_ERRORF("mknod /dev/kmsg failed: %s", strerror(errno));

    LOG_INFOF("Created basic device nodes in /dev");
}

static void redirect_to_kmsg(void) {
    int fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "Failed to open /dev/kmsg: %s\n", strerror(errno));
        return;
    }
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    close(fd);
    // Now printf/fprintf(stderr, …) go into dmesg
}

int rdinit_main(void) {
    LOG_INFOF("rdinit_main: starting as PID 1 init (pid=%d)", getpid());
    setup_mounts_and_dev();
    //setup_consoles_from_cmdline();
    redirect_to_kmsg();

    // Start proxy server
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        perror("socketpair");
        exit(1);
    }
    pid_t proxy_pid = fork();
    if (proxy_pid == 0) {
        close(sv[1]);
       setup_mounts_and_dev_unshare();
        redirect_to_kmsg();
        proxy_loop(sv[0], sv[0]);
        close(sv[0]);
        exit(0);
    }
    close(sv[0]);
    LOG_INFOF("rdinit_main: proxy server started (pid=%d)", proxy_pid);

    // Read kernel cmdline
    char cmdline[4096] = {0};
    FILE *f = fopen("/proc/cmdline", "r");
    if (f) {
        fread(cmdline, 1, sizeof(cmdline)-1, f);
        fclose(f);
    }
    LOG_INFOF("rdinit_main: kernel cmdline = \"%s\"", cmdline);

    // Extract init= if present (must start with "init=")
    char *init_target = "/init";
#if 0
    char *tok = strtok(cmdline, " ");
    while (tok) {
        if (strncmp(tok, "init=", 5) == 0) {
            init_target = tok + 5;
            LOG_INFOF("rdinit_main: found init= argument: %s", init_target);
            break;
        }
        tok = strtok(tok, " ");
    }
#endif
    LOG_INFOF("rdinit_main: found init = %s ", init_target);
    // Fail‑safe list
    const char *fallbacks[] = {
        init_target,
        "/init",
        "/system/bin/init",
        "/sbin/init",
        "/bin/init",
        "/bin/sh",
        NULL
    };

    // Try each candidate
    for (int i = 0; fallbacks[i]; i++) {
        const char *target = fallbacks[i];
        if (!target) continue;
        LOG_INFOF("rdinit_main: trying candidate %s", target);

        if (validate_command(target) == 0) {
            char *argv[] = { (char *)target, NULL };
            char buffer[1024];
            size_t len = build_tlv_command(TLV_SPAWN, 1, argv, buffer, sizeof(buffer));
            write(sv[1], buffer, len);
            LOG_INFOF("rdinit_main: launched %s via proxy", target);
            goto loop;
        }
    }

    LOG_ERRORF("rdinit_main: no valid init target found, system may be unusable");

loop:
    // Reap children forever
    while (1) {
        int status;
        pid_t pid = waitpid(-1, &status, WNOHANG);
        if (pid > 0) {
            LOG_INFOF("Reaped child %d exit=%d", pid, WEXITSTATUS(status));
        }
        sleep(1);
    }
    return 0;
}

// child_main: bind stdio to console and exec the provided command.
// argc/argv here are the child's arguments (argv[0] is the program to exec).
int child_main(int argc, char **argv) {
    // Determine console from cmdline or fallback
    const char *tty = parse_console_from_cmdline(); // implement if not present
    if (!tty) tty = "/dev/console";

    redirect_to_console(tty);

    if (argc < 1 || !argv[0]) {
        fprintf(stderr, "child_main: no command provided\n");
        return 1;
    }

    // Validate executable before exec
    if (!validate_command(argv[0])) {
        fprintf(stderr, "child_main: command not found or not executable: %s\n", argv[0]);
        return 1;
    }

    // Exec the requested program; if exec fails, print error and exit
    execvp(argv[0], argv);
    fprintf(stderr, "child_main: execvp failed: %s\n", strerror(errno));
    return 1;
}

// Run proxy as a background service. Reuse rdinit setup steps (mounts, dev nodes, kmsg).
// Returns 0 in the parent (service started) or nonzero on failure.
int proxy_main(int argc, char **argv) {
    // System role: ensure logging and mounts are prepared like rdinit
    redirect_to_kmsg();

    if (setup_mounts_and_dev() != 0) {
        fprintf(stderr, "proxy_main: setup_mounts_and_dev failed\n");
        return 1;
    }

    // Create a socketpair for proxy loop communication
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        fprintf(stderr, "proxy_main: socketpair failed: %s\n", strerror(errno));
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "proxy_main: fork failed: %s\n", strerror(errno));
        close(sv[0]); close(sv[1]);
        return 1;
    }

    if (pid > 0) {
        // Parent: detach and return success (background service started)
        close(sv[1]);

        // Optionally write the child PID to a pidfile or log it
        LOG_INFOF("proxy_main: started background proxy pid=%d", pid);

        // Parent should close standard fds if you want it fully daemonized,
        // but keep behavior minimal: return to caller so init can continue.
        return 0;
    }

    // Child: become the background proxy process
    close(sv[0]);

    // Create new session and detach from controlling tty
    if (setsid() < 0) {
        fprintf(stderr, "proxy_main(child): setsid failed: %s\n", strerror(errno));
        // continue anyway
    }

    // Optional: chdir to / to avoid blocking mounts
    chdir("/");

    // Close inherited file descriptors except sv[1], STDIN/OUT/ERR if needed
    for (int fd = 3; fd < 256; fd++) {
        if (fd != sv[1]) close(fd);
    }

    // Reuse rdinit logging behavior
    redirect_to_kmsg();

    // Run the proxy loop on the socket end
    int rc = proxy_loop(sv[1]);

    // If proxy_loop returns, exit child process
    _exit(rc);
}
int main(int argc, char **argv) {
    // Debug bypass: force rdinit_main regardless of PID
    if (argc >= 2 && strcmp(argv[1], "--debug") == 0) {
        LOG_INFOF("Debug mode: forcing rdinit_main (pid=%d)", getpid());
        return rdinit_main(argc, argv);
    }

    // If PID 1 and no arguments, assume rdinit role
    if (getpid() == 1 && argc < 2) {
        return rdinit_main(argc, argv);
    }

    // Help output
    if (argc < 2 || strcmp(argv[1], "--help") == 0) {
        print_help(argv[0]);
        return 0;
    }

    // Command dispatch based on argv[0] (binary name) or argv[1] (first argument)
    const char *cmd = argv[1];
    const char *base = strrchr(argv[0], '/');
    base = base ? base + 1 : argv[0];

    if (!strcmp(base, "rdinit") || !strcmp(cmd, "rdinit")) {
        return rdinit_main(argc - 1, &argv[1]);
    } else if (!strcmp(base, "proxy") || !strcmp(cmd, "proxy")) {
        return proxy_main(argc - 1, &argv[1]);
    } else if (!strcmp(base, "spawn") || !strcmp(cmd, "spawn")) {
        return spawn_main(argc - 1, &argv[1]);
    } else if (!strcmp(base, "sudo") || !strcmp(cmd, "sudo")) {
        return sudo_main(argc - 1, &argv[1]);
    } else if (!strcmp(base, "chroot") || !strcmp(cmd, "chroot")) {
        return chroot_main(argc - 1, &argv[1]);
    } else if (!strcmp(base, "child") || !strcmp(cmd, "child")) {
        return child_main(argc - 1, &argv[1]);
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        print_help(argv[0]);
        return 1;
    }
}
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <sys/resource.h>

/* Assumed existing elsewhere in the project:
 *   int setup_mounts_and_dev(void);
 *   int proxy_loop(int fd);
 *   int validate_command(const char *path);
 *   void redirect_to_kmsg(void);
 *   void redirect_to_console(const char *path);
 *
 * If any of these are missing, provide minimal stubs or adapt calls.
 */

#define CMDLINE_BUFSZ 1024

/* -------------------------
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <sys/resource.h>

/* Assumed existing elsewhere in the project:
 *   int setup_mounts_and_dev(void);
 *   int proxy_loop(int fd);
 *   int validate_command(const char *path);
 *   void redirect_to_kmsg(void);
 *   void redirect_to_console(const char *path);
 *
 * If any of these are missing, provide minimal stubs or adapt calls.
 */

#define CMDLINE_BUFSZ 1024

/* -------------------------
 * Common parsing utilities
 * ------------------------- */

/* Read /proc/cmdline into a bounded buffer and NUL-terminate.
 * Guarantees the read loop writes at most CMDLINE_BUFSZ-1 bytes
 * and sets buf[CMDLINE_BUFSZ-1] = '\0' if the input is longer.
 */
static void read_cmdline_buf(char *buf, size_t bufsz) {
    FILE *f = fopen("/proc/cmdline", "r");
    if (!f) {
        buf[0] = '\0';
        return;
    }

    size_t n = 0;
    int c;
    while (n < (bufsz - 1) && (c = fgetc(f)) != EOF) {
        buf[n++] = (char)c;
    }
    /* If buffer filled, ensure we still NUL-terminate at last slot */
    buf[n] = '\0';

    /* If we stopped because buffer full, drain the rest of the stream to EOF */
    if (c != EOF) {
        while ((c = fgetc(f)) != EOF) { /* discard */ }
    }

    fclose(f);
}

/* Return pointer to static buffer containing the init path or NULL.
 * Matches only the literal token " init=" (leading space).
 * The returned pointer points to a static buffer owned by this function.
 * Blacklists common self names to avoid self-looping.
 */
static const char *parse_init_param(void) {
    static char cmdline[CMDLINE_BUFSZ];
    read_cmdline_buf(cmdline, sizeof(cmdline));

    char *pos = strstr(cmdline, " init=");
    if (!pos) return NULL;

    char *val = pos + 6; /* skip " init=" */
    if (!*val) return NULL;

    static char init_path[CMDLINE_BUFSZ];
    size_t i = 0;
    while (i < (sizeof(init_path) - 1) && *val && *val != ' ' && *val != '\t' && *val != '\n' && *val != '\r') {
        init_path[i++] = *val++;
    }
    init_path[i] = '\0';

    /* Defensive blacklist to avoid launching ourselves */
    if (strstr(init_path, "rdinit") || strstr(init_path, "proxy") ||
        strstr(init_path, "spawn")  || strstr(init_path, "child") ||
        strstr(init_path, "sudo")   || strstr(init_path, "chroot")) {
        return NULL;
    }

    return init_path;
}

/* Parse console= token using the same simple rules as parse_init_param.
 * Matches only " console=" (leading space). Returns static buffer or NULL.
 */
static const char *parse_console_from_cmdline(void) {
    static char cmdline[CMDLINE_BUFSZ];
    read_cmdline_buf(cmdline, sizeof(cmdline));

    char *pos = strstr(cmdline, " console=");
    if (!pos) return NULL;

    char *val = pos + 9; /* skip " console=" */
    if (!*val) return NULL;

    static char console_path[CMDLINE_BUFSZ];
    size_t i = 0;
    while (i < (sizeof(console_path) - 1) && *val && *val != ' ' && *val != '\t' && *val != '\n' && *val != '\r') {
        console_path[i++] = *val++;
    }
    console_path[i] = '\0';

    return console_path;
}

/* -------------------------
 * Logging / console helpers
 * ------------------------- */

/* Redirect stdout/stderr to /dev/kmsg if available.
 * This is non-fatal: on failure we leave stdio as-is and return -1.
 */
static int redirect_to_kmsg(void) {
    int fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;

    if (dup2(fd, STDOUT_FILENO) < 0) { close(fd); return -1; }
    if (dup2(fd, STDERR_FILENO) < 0) { close(fd); return -1; }
    close(fd);
    return 0;
}

/* Redirect stdio to a console device path (e.g., /dev/console or /dev/ttyS0).
 * Returns 0 on success, -1 on failure.
 */
static int redirect_to_console(const char *path) {
    if (!path) return -1;
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;

    if (dup2(fd, STDIN_FILENO) < 0) { close(fd); return -1; }
    if (dup2(fd, STDOUT_FILENO) < 0) { close(fd); return -1; }
    if (dup2(fd, STDERR_FILENO) < 0) { close(fd); return -1; }

    /* Keep fd open only if it's not one of std{in,out,err} */
    if (fd > STDERR_FILENO) close(fd);
    return 0;
}

/* -------------------------
 * Background proxy service
 * ------------------------- */

/* Start proxy as a background service. This reuses rdinit setup steps
 * (mounts/dev creation) so the proxy runs in a prepared environment.
 *
 * Behavior:
 *  - Parent returns 0 on success (proxy started in background).
 *  - Child becomes the proxy daemon and runs proxy_loop(fd).
 *  - On failure, returns non-zero.
 *
 * Notes:
 *  - setup_mounts_and_dev() must be idempotent.
 *  - proxy_loop(int fd) is expected to take ownership of the socket fd.
 */
int proxy_main(int argc, char **argv) {
    /* Prepare logging early so we can record failures */
    redirect_to_kmsg();

    if (setup_mounts_and_dev() != 0) {
        fprintf(stderr, "proxy_main: setup_mounts_and_dev failed: %s\n", strerror(errno));
        return 1;
    }

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        fprintf(stderr, "proxy_main: socketpair failed: %s\n", strerror(errno));
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "proxy_main: fork failed: %s\n", strerror(errno));
        close(sv[0]); close(sv[1]);
        return 1;
    }

    if (pid > 0) {
        /* Parent: close child end and return success (background service started) */
        close(sv[1]);
        /* Optionally log the background PID */
        fprintf(stderr, "proxy_main: background proxy started pid=%d\n", pid);
        return 0;
    }

    /* Child: become the background proxy process */
    close(sv[0]);

    /* Detach: new session, optional chdir, reset umask */
    if (setsid() < 0) {
        /* non-fatal */
    }
    chdir("/");
    umask(0);

    /* Close all fds except sv[1], STDIN/OUT/ERR if desired.
     * Use sysconf to get max fd limit.
     */
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0) maxfd = 256;
    for (int fd = 3; fd < (int)maxfd; fd++) {
        if (fd == sv[1]) continue;
        close(fd);
    }

    /* Ensure logging is attached to kmsg in the daemon child */
    redirect_to_kmsg();

    /* Run the proxy loop on the socket end; proxy_loop should not return under normal operation.
     * If it returns, exit with its return code.
     */
    int rc = proxy_loop(sv[1]);
    _exit(rc);
}

/* -------------------------
 * child_main: console-bound exec
 * ------------------------- */

/* child_main receives argc/argv where argv[0] is the program to exec.
 * It binds stdio to the console (from cmdline or /dev/console) and execs the program.
 */
int child_main(int argc, char **argv) {
    const char *tty = parse_console_from_cmdline();
    if (!tty) tty = "/dev/console";

    if (redirect_to_console(tty) < 0) {
        /* If console redirect fails, try /dev/console as a last resort */
        redirect_to_console("/dev/console");
    }

    if (argc < 1 || !argv[0]) {
        fprintf(stderr, "child_main: no command provided\n");
        return 1;
    }

    if (!validate_command(argv[0])) {
        fprintf(stderr, "child_main: command not found or not executable: %s\n", argv[0]);
        return 1;
    }

    execvp(argv[0], argv);
    /* If execvp returns, it failed */
    fprintf(stderr, "child_main: execvp failed: %s\n", strerror(errno));
    return 1;
}
