# Remote debugging (GDB remote protocol)

Paranoia can debug a program or a firmware image that a **server** runs: `gdbserver` (Linux, on this or another machine, x86, x86-64, ARM, AArch64 and more) or QEMU's built-in gdbstub (`-s -S`: bare-metal firmware, Cortex-M, AArch64, RISC-V, …). This is how you debug something Paranoia cannot start itself: a macOS or Android program under a server, a microcontroller image in an emulator, an embedded Linux board.

## Using it

1. Start a server, for example:

```bash
gdbserver 127.0.0.1:1234 ./sample                        # a Linux program
qemu-system-arm -M lm3s6965evb -kernel fw.elf -s -S      # firmware, stopped at reset, gdbstub on :1234
```

2. Open the same file in Paranoia (for firmware: the `.bin` or `.hex` with its architecture and base, see [FIRMWARE.md](FIRMWARE.md)).
3. Debug → **Connect to GDB server…**, `127.0.0.1:1234`. If the program is relocated on the target (a PIE under `gdbserver`), add the address it is loaded at: `127.0.0.1:1234 7ffff7d8a000`. A native dialog shows the host and port and asks you to confirm.

The debugger panel, breakpoints (F9), step into / over (F7 / F8), run to cursor, pause and stop work as with a local program. Registers come from the server's own description, so a Cortex-M shows `xpsr` and the banked registers the server reports. *Stop* detaches from the server; it does not kill what the server runs.

## What it sends, and the security rules

This is the one place the engine opens a socket. Only when you ask:

- the desktop app shows the host and port in a **native** confirmation first (a page cannot answer it); a server that is not on this computer gets a stronger warning, because the protocol is not encrypted;
- the main process checks the address (a host name or IP and a port, nothing else) before the engine sees it;
- the engine connects to that one address and sends debugger packets only: no files, no analysis results, nothing from your workspace.
- what the server sends is not trusted for size: a packet is at most 1 MiB and unpacks to at most 2 MiB, noise that is not a packet is dropped, a target description may list at most 4096 registers of at most 8192 bits and is read in at most 4096 parts, and every wait has a time limit. A server that breaks a limit is disconnected, not obeyed. A test runs a server that never stops talking.

A GDB server is trusted by design: it decides what runs, and what Paranoia shows is what it reports. Do not connect to a server you do not control or trust. See [SECURITY-DESIGN.md](SECURITY-DESIGN.md#remote-debugging).

## What is supported

Register layout from `target.xml` (with includes) or a fixed layout for x86, x86-64, ARM and AArch64; memory reads; software breakpoints (`Z0`, falling back to hardware `Z1`); continue, step, step over calls (x86, x86-64, AArch64, ARM and Thumb call encodings), interrupt; console output (`O` packets) into the log; signals other than SIGTRAP are shown and passed on at the next continue.

## What is not (yet)

- Writing registers or memory from the UI, and watchpoints.
- Several threads or processes: the thread the server reports is the one shown.
- A UNIX socket, serial line, or TLS tunnel: use `ssh -L` to reach a remote server securely.
- Tested against a fake server in the unit tests (packet framing, escaping, run-length encoding, `target.xml` includes, breakpoints, stepping, exit) and not yet against a real `gdbserver` or QEMU: that needs a Linux or QEMU installation this repository's CI does not have. Please report what a real server does differently.
