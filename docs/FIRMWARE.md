# Firmware and raw images

Paranoia opens files that have no PE, ELF or Mach-O header: a flat `.bin` dumped from a flash chip, an Intel HEX file, a Motorola S-record file. Such a file cannot say which CPU it is for or where it is loaded, so you say, or let Paranoia suggest.

## Opening one

**Desktop app.** Open the file as usual. When it has no header, a dialog asks for the architecture and the load address; the fields start from the engine's suggestion. File → *Open firmware or raw image…* skips the failed attempt.

**Command line.** The options work with every command:

```bash
paranoia guess fw.bin                       # suggests --arch and --base, with the reasons
paranoia functions fw.bin --arch thumb --base 0x08000000
paranoia functions fw.hex --arch thumb      # Intel HEX and S-record carry their addresses
paranoia disasm fw.bin --arch auto          # take the guess for both
```

| Option | Meaning |
| --- | --- |
| `--arch` | `x86`, `x86-64`, `arm`, `thumb` (Cortex-M and other Thumb-2-only cores), `arm64`, `mips`, `mips64`, `ppc`, `ppc64`, `riscv32`, `riscv64`, or `auto` (the guess below) |
| `--base` | load address (hex) of a plain `.bin`; ignored for HEX and S-record files |
| `--entry` | entry point (hex); default: the reset handler, the file's start address, or the first byte |
| `--big-endian` | default is little-endian, except PowerPC |

## What the file becomes

- One mapped range per segment (a HEX file with two flash banks is two ranges, at their own addresses). The ranges are readable and executable; there is no way to tell code from data in a flat image, so analysis starts from the entry point and the vector table, not from "all executable bytes".
- HEX and S-record checksums are verified; a damaged line is reported with its number and nothing is loaded. Overlapping records are applied in file order. The hashes and the knowledge-base key (SHA-256) are those of the **decoded image**, not of the text file.
- Images larger than 256 MiB are refused.

`paranoia mcp` opens firmware too: `open_binary` takes `arch` (or `auto`), `base`, `entry` and `big_endian`; without an architecture it refuses the file and puts the guess in the error, so an agent can retry.

## Cortex-M

When the architecture is `thumb` and the image starts with a vector table (a stack pointer in RAM and valid Thumb handlers for reset, NMI and HardFault, all inside the image), Paranoia:

- names the table `__vectors` and marks its words as data;
- makes every handler a function: `Reset_Handler`, `NMI_Handler`, `HardFault_Handler`, `MemManage_Handler`, `BusFault_Handler`, `UsageFault_Handler`, `SVC_Handler`, `DebugMon_Handler`, `PendSV_Handler`, `SysTick_Handler`, and `IRQn_Handler` for the vendor interrupts;
- calls a handler that three or more vectors share `Default_Handler`;
- uses the reset handler as the entry point.

Names are the ARM CMSIS conventions, not a lookup of the part: Paranoia does not know which peripheral IRQ 17 is. SVD files (peripheral names and register maps) are not supported yet.

## How the guess works, and when it is wrong

`paranoia guess` and the dialog's suggestion are heuristics, and say why:

1. **Cortex-M vector table at offset 0.** The architecture is `thumb`. The base is the roundest address (largest power-of-two alignment) that keeps every handler inside the image and the table before the first handler; with strings in the image, the candidate that makes the most pointers land on a string start wins.
2. **The CPU, from the machine code.** Every compiler leaves the same marks at function boundaries: `ret`, a frame set-up, a stack adjustment. Paranoia counts each CPU's marks (`ret` and `stp x29, x30` on AArch64, `bx lr` and `push {…, lr}` on ARM and Thumb, `jr ra` on MIPS in both byte orders, `blr` and `mflr` on PowerPC, `ret` and `addi sp, sp, -N` on RISC-V, frame set-ups on x86 and x86-64), compares each count with what random bytes would give, and answers only when one CPU is far above chance and clearly ahead of the runner-up. It needs a few KiB of code and stays silent otherwise.
3. **A base address**, only when at least 8 pointers to strings agree on it and no other candidate has half as many.

Wrong guesses are visible at once: calls and pointers lead into the middle of nowhere, and the listing shows no strings where there should be some. Change the base and open again.

**How well it works.** The CPU guess was scored on the executable sections of 37 real files (x86, x86-64 and AArch64: Windows DLLs, Go, Rust and C programs, ELF, Mach-O and PE): 36 right, 1 silent, 0 wrong. MIPS, PowerPC, RISC-V, ARM and Thumb have only been shown working on synthetic data, so for those the guess has not been measured on real code. The base-address guess and the vector-table logic have been tested on synthetic images only; how often they are right on real firmware is not known.

## Finding functions in a raw image

A raw x86-64, AArch64, ARM or Thumb image has no unwind table or symbols, so besides the entry point and the vector table Paranoia scans for function starts: a frame set-up (for example `push rbp; mov rbp, rsp`, `sub rsp, N`, `stp x29, x30, [sp, #-N]!`, `push {…, lr}`, and Go's stack-check prologues) right after a `ret`, padding or a branch, accepted only when the code there decodes. When that is spent, a second, looser pass accepts a start right after a `ret` or padding with no prologue, which is where leaf functions are.

Measured by cutting the executable section out of real files, opening it as a raw image at its own address, and comparing with what the headers-and-unwind-table analysis finds:

| File (section dumped) | CPU | reference functions | found | not in reference |
| --- | --- | ---: | ---: | ---: |
| `comctl32.dll` | x86-64 | 1 609 | 99.8 % | 5.0 % |
| `gofmt` (Go, PE) | x86-64 | 3 284 | 98.8 % | 3.0 % |
| `notepad.exe` | x86-64 | 424 | 96.7 % | 20.5 % |
| `shlwapi.dll` | x86-64 | 1 193 | 94.8 % | 37.5 % |
| `rustfmt` (Rust, MinGW) | x86-64 | 16 225 | 63.7 % | 7.7 % |
| `gofmt` (Go, Linux) | AArch64 | 3 080 | 98.1 % | 8.0 % |
| `gofmt` (Go, macOS) | AArch64 | 3 116 | 98.0 % | 7.9 % |

"Not in reference" is not an error rate for the PE files: the unwind table leaves leaf functions out, so some of those are real. For the two Go rows the reference (Go's function table) is complete, so there it is a fair estimate of false functions: 3 % and 8 %. Rust code built with MinGW is the weak case: many of its functions are frameless and follow no recognisable pattern. Thumb and ARM use the same scan, tested on synthetic code only.

## Not yet

- Pseudocode for Thumb (the listing, graph, cross references and function memory work).
- Named memory regions and SVD files; peripheral register names.
- Opening firmware in the browser build.
- Function discovery for MIPS, PowerPC and RISC-V raw images (they get the entry point and what the descent follows).
