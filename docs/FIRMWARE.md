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
| `--arch` | `x86`, `x86-64`, `arm`, `thumb` (Cortex-M and other Thumb-2-only cores), `arm64`, `mips`, `mips64`, `ppc`, `ppc64`, `riscv32`, `riscv64`, or `auto` |
| `--base` | load address (hex) of a plain `.bin`; ignored for HEX and S-record files |
| `--entry` | entry point (hex); default: the reset handler, the file's start address, or the first byte |
| `--big-endian` | default is little-endian, except PowerPC |

## What the file becomes

- One mapped range per segment (a HEX file with two flash banks is two ranges, at their own addresses). The ranges are readable and executable; there is no way to tell code from data in a flat image, so analysis starts from the entry point and the vector table, not from "all executable bytes".
- HEX and S-record checksums are verified; a damaged line is reported with its number and nothing is loaded. Overlapping records are applied in file order. The hashes and the knowledge-base key (SHA-256) are those of the **decoded image**, not of the text file.
- Images larger than 256 MiB are refused.

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
2. **Other images.** Only a base, and only when at least 8 pointers to strings agree on it and no other candidate has half as many.

It will not guess the architecture of anything that is not a Cortex-M image. Wrong guesses are visible at once: calls and pointers lead into the middle of nowhere, and the listing shows no strings where there should be some. Change the base and open again.

Tested on synthetic images built in the tests (vector table at four different bases, string-pointer tables, HEX and S-record of every address size) and on the whole path from file to function list. It has not been measured on a corpus of real firmware, so how often the guess is right on real parts is not known.

## Not yet

- Pseudocode for Thumb (the listing, graph, cross references and function memory work).
- Named memory regions and SVD files; peripheral register names.
- Guessing the architecture of other raw images (a plain AArch64 or MIPS `.bin` needs `--arch`).
- Opening firmware in the browser build and through `paranoia mcp`.
