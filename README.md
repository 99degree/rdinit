# rdinit

`rdinit` is a lightweight init container manager designed to run **unmodified Android** inside a container.  
When the Linux kernel boots, it expects the very first userland process (PID 1) to be either `init` or `rdinit`.  
This project provides a minimal `rdinit` that sets up the right namespaces and then launches Android’s own `/init` process, allowing stock Android to run in a container without modification.

---

## Why rdinit?

Running Android in a container is tricky because the system assumes it is PID 1 and owns the root namespace.  
`rdinit` bridges that gap by:

- Acting as PID 1 itself.
- Creating new namespaces (mount, PID, etc.).
- Preparing `/dev`, `/proc`, and `/sys` for Android.
- Handing control over to Android’s `/init`.

This way, Android runs as if it were booting normally, but inside a controlled container environment.

---

## How it works

1. **rdinit starts as PID 1**  
   It sets up a baseline environment and spawns a proxy process.

2. **Proxy process**  
   The proxy manages namespace setup and listens for requests from helper tools (`ns-su`, `ns-chroot`).

3. **IPC via abstract UNIX socket**  
   Communication between helpers and the proxy uses an abstract socket (`\0nssu.sock`), so there are no lock files or mount‑namespace visibility issues.

4. **Helpers**  
   - `ns-su`: run a command inside Android’s PID namespace.  
   - `ns-chroot`: run a command inside a new chroot.  
   - `ns-chroot-devtmpfs`: run inside a chroot with a fresh `/dev`.

---

## Usage

### Boot with rdinit
Add to kernel command line:
```bash
init=/rdinit
