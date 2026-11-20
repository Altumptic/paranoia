# Is the pseudocode right? Running it against the machine

Pseudocode that looks plausible can still compute something else. For Thumb-2 (Cortex-M) Paranoia checks the generated C against real hardware semantics, with no compiler involved:

1. A generator writes random Thumb-2 functions: ALU and shift instructions, loads and stores of every size (also sign-extending and with pre/post-index write-back), `if` and `if`/`else` on every condition after `cmp`, `tst` and flag-setting instructions, `cbz`/`cbnz`, counting loops (`do … while` and `while`), a `push {r4, r5, lr}` frame with `r4` as a variable, 32-bit forms (`movw`/`movt`, shifted-register operations, `addw`/`subw`, `mul`/`mla`, `udiv`/`sdiv`, `uxtb`/`sxtb`/`uxth`/`sxth`).
2. They are assembled into one image together with a driver, and run in **QEMU's Cortex-M model** (`lm3s6965evb`) on ten input sets each (edge values and random ones). The driver prints every result over the UART.
3. The same image is opened as a raw Thumb image, analysed, and the **text** of each function's pseudocode is parsed and executed by a small interpreter for the C subset Paranoia writes (`int` arithmetic, `(unsigned)` and `(int)` casts, `*(uintN_t *)` memory, `if`/`else`, `while`, `do`, `for`, `goto`, `switch`). Its integer rules are C's: an `int` shifts arithmetically, a literal like `0xffffffcc` is unsigned and makes the expression unsigned.
4. The results must be identical: QEMU's `r0` and the C function's return value, with the memory the function wrote (a scratch buffer) feeding later loads.

The test is `thumb_pseudocode_matches_qemu` in `crates/paranoia-core/src/qemu_diff.rs`. It runs when `PARANOIA_QEMU` names a QEMU, and in CI (job *Thumb pseudocode vs QEMU*, six fixed seeds of 600 functions):

```powershell
$env:PARANOIA_QEMU = "qemu-system-arm"          # on Windows with WSL: "wsl -d kali -- qemu-system-arm", plus PARANOIA_QEMU_WSL=1 and PARANOIA_QEMU_DIR=D:/tmp
$env:PARANOIA_QEMU_FUNCS = "600"; $env:PARANOIA_QEMU_SEED = "7"
cargo test -p paranoia-core --lib thumb_pseudocode_matches_qemu -- --nocapture
```

## What it found

The first run agreed on 39 of 60 functions. The comparison found, and the fixes cover (x86 and AArch64 pseudocode share the code, so they were fixed there too):

- a flag-setting result that only a branch reads was dropped, leaving a raw register (`if (rax == 0)`) in the C;
- an expression was moved past an assignment to the same variable (`lsrs r2, r0, #3` then `movs r0, #0xed` then `orrs r2, r0` read the new `r0`), and a copy was propagated across the same kind of assignment;
- a load was moved past a store through a chain of inlined values;
- a logical shift right was printed as `>>` on an `int`, which is arithmetic in C; an arithmetic shift of an expression C types as unsigned was logical; a signed comparison with a literal such as `0xffffffcc`, or with an operand C types as unsigned, was unsigned; a signed division of such an operand was unsigned;
- loops: an argument read only through a loop's phi was not a parameter;
- Thumb lifter: a short `b` and a pre-indexed `ldr`/`str` used the wrong address; `ldrsb`/`ldrsh` did not sign-extend; constants were folded in 64 bits (so `sxtb` of a constant was wrong); 32-bit `push`/`pop` were kept as text.

After the fixes 40 000 random functions (40 seeds of 1 000, ten input sets each) agree.

## What it does not cover

Honest limits of this check, so a green run is not read as more than it is:

- Only the instructions listed above. `it` blocks, `adc`/`sbc`, `tbb`/`tbh`, `ldm`/`stm` other than `push`/`pop`, `ldrd`/`strd`, `clz`, `rev`, VFP and everything else are kept as text by the lifter and are not compared.
- No calls, no stack variables beyond the frame, no function pointers, no jump tables: the functions are leaves of 5–40 instructions. Real compiled code mixes all of these.
- Shifts by a register are left out: `lsls r0, r1` with an amount of 32 or more gives 0 on the machine and is undefined in C, which the pseudocode prints as `x << y`.
- Branch conditions after flag-setting instructions other than `cmp`/`tst`/`cmn` are only compared for `eq`, `ne`, `mi` and `pl` (the result alone decides them); overflow conditions (`vs`, `vc`) are written as `__flags_o` and not compared.
- A function whose `r0` is not written last is decompiled as `void` (the return value is a guess), so its result is not compared, only its memory effects.
- QEMU is a model of the core, not silicon; the instructions used behave the same on any Cortex-M3/M4.
- It checks that the C computes what the code computes, not that it is *readable* or that variables and types are the ones a programmer wrote.

The same idea is not yet applied to x86-64 or AArch64 (those are checked on real programs for structure and call targets, see [BENCHMARK.md](BENCHMARK.md) and [ROADMAP.md](ROADMAP.md)).
