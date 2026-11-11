# Function memory

Function memory recognises the same function in different files: a new version of a program, another build of it, or a sample from the same family. It does two things:

- **Compare two files.** Which functions are identical, which changed and how much, which were added or removed. This is what BinDiff and Diaphora do; use it to find what a patch fixed or what a new malware version added.
- **Remember functions.** Functions you named in one file are recognised in the next one, and their names, comments and variable names come with them. IDA's Lumina does this with a shared server. Here the database is a file on your computer, and nothing is sent anywhere.

Both work on x86, x64, AArch64 and the other architectures Paranoia disassembles.

## Using it

In the app:

- **Analysis → Compare with another file…** opens a second file and matches it against the one you have open. You get the changed functions (least similar first), the ones that exist in only one file, and both versions of a function side by side with the differing lines highlighted. **Take names** copies names from the other file to functions that only have an automatic name here (one undo step).
- **Analysis → Function memory…** has **Learn this file**, which remembers the functions you named (optionally also names from symbols, exports and debug info), and **Recognise**, which lists the functions of the open file the database knows. Pick the ones you want and press **Apply** (one undo step).

From the command line:

```bash
paranoia diff old.exe new.exe                    # summary, changed, removed and added functions
paranoia memory learn sample-a.exe               # remember the names you gave in the app
paranoia memory learn --symbols libfoo.so        # also learn symbol names, e.g. from a debug build
paranoia memory recall sample-b.exe              # what the database recognises in another file
paranoia memory recall sample-b.exe --apply      # write the names into the app's workspace (close the app first)
paranoia memory stats
paranoia memory export team.jsonl                # share with a colleague; `import` on their side
paranoia memory forget <sha256>                  # drop everything learned from one file
```

The database is `memory.redb` next to the app's workspace (`%APPDATA%\Paranoia` on Windows). `--db FILE` uses another one, for example one per case.

Agents can use it too: `compare_binaries` is always available in `paranoia mcp`, and `recognize_functions` with `--memory` (see [MCP.md](MCP.md)).

## How functions are matched

Each function gets a fingerprint with no addresses in it:

| Part | What it is | Survives |
| --- | --- | --- |
| Exact | Hash of the bytes with addresses, call targets and references masked out | Relinking, moving to another address |
| Shape | Hash of the instruction sequence reduced to mnemonic and operand kinds (`mov r,m`) | Different registers, different data addresses |
| Sketch | MinHash of instruction triples, 64 values | Edits: two sketches agree in about as many places as the triples overlap |
| Anchors | Hashes of the imports it calls, the strings it uses and unusual constants | Rearranged code |
| Shape of the graph | Blocks, edges, loops, calls | |

Comparing two files runs in passes, from certain to likely. A function matched by one pass is not reconsidered:

1. the same real name on both sides (`paranoia diff --no-names` turns this off);
2. identical masked bytes, if that fingerprint occurs once on each side;
3. identical instruction shape, also only when unique;
4. the same set of anchors;
5. the call graph: callers and callees of matched pairs are matched among themselves, scored on the code and on how many of their neighbours already agree;
6. similar code: candidates that share a band of their sketches, best score first, neighbours breaking ties;
7. the call graph again;
8. identical copies left on both sides in equal numbers are paired in address order, then the call graph once more.

Functions that occur more than once with identical code (small wrappers, compiler-generated helpers) aren't matched on code alone in the early passes; their callers and callees tell the copies apart, and whatever is left is paired by position.

Recognising from the database works the same way without a second file. Candidates come from an index of exact hashes and sketch bands. A first round accepts unambiguous matches on code alone. Later rounds use what the database remembers about each function's calls: once a caller is recognised, the functions it is known to call become candidates for its callees, and agreeing neighbours raise a candidate's score. A name is never offered when two different names score about the same, and one name goes to at most one function.

## How accurate it is

Measured with `paranoia diff --check-names` and `paranoia memory recall --check-names`, which hide the files' names from the matcher and then compare its answer with them. The files are Go's `gofmt` (about 3 000 functions) built from the same source with different compiler settings, and two versions of Windows' `comctl32.dll` that share their exported names.

| Files | Compare: right | wrong | Recognise: right | wrong |
| --- | --- | --- | --- | --- |
| `GOAMD64=v1` vs `v3` (different instruction selection) | 100 % | 0 % | 88.7 % | 0 % |
| bounds checks on vs off (`-gcflags=all=-B`) | 98.3 % | 0.4 % | 86.6 % | 0.1 % |
| inlining on vs off (`-gcflags=all=-l`) | 84.4 % | 4.8 % | 43.2 % | 1.2 % |
| `comctl32.dll` 5.82 vs 6.0 (largely rewritten) | 61.6 % | 2.3 % | | |

"Compare" counts functions of 16 or more instructions whose name occurs once in each file; "Recognise" counts all named functions of 4 or more instructions, after learning the first file of the pair. Without inlining, about 1 400 of the second build's functions don't exist in the first one, so the best possible recognition there is around 70 %.

Where it is weak:

- Functions shorter than 4 instructions aren't remembered or matched on their own.
- Heavy changes in inlining or optimisation level change most of the code.
- Obfuscated or packed code has to be unpacked first.

The numbers come from our own runs on the machine that wrote this page; run the same commands on your files to see how it does on them.

## What is stored

For each remembered function: its name, your comment on it, comments inside it (by offset), renamed and typed pseudocode variables, the names of the named functions it calls, the fingerprint, and the name and SHA-256 of the file it was learned from. No code, no strings from the file. Fingerprint hashes are one-way, but the anchors are hashes of the file's strings and imports, so someone holding your database could check whether a function uses a string they already know.
