// Benchmark harness: decompile every function in the current program and dump
// one JSON object per function (plus a header line per file) for bench/run.mjs.
//
// Run with:
//   analyzeHeadless <projectDir> <projectName> -import <binary> \
//       -postScript DecompileAll.java -scriptPath bench/tools/ghidra \
//       -deleteProject
//
// Environment:
//   PARANOIA_BENCH_OUT  directory for <sha256>.ghidra.jsonl files (required)
//   PARANOIA_BENCH_DECOMP_TIMEOUT  per-function decompiler timeout, seconds (default 120)
//
// @category Benchmark
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.LinkedHashSet;
import java.util.Set;

public class DecompileAll extends GhidraScript {

    private static String esc(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder b = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
            }
        }
        return b.toString();
    }

    private static String addrStr(Address a) {
        if (a == null) {
            return "null";
        }
        return "\"0x" + Long.toHexString(a.getOffset()) + "\"";
    }

    private static String addrSpace(Address a) {
        return a == null ? "null" : "\"" + esc(a.getAddressSpace().getName()) + "\"";
    }

    @Override
    public void run() throws Exception {
        String outDir = System.getenv("PARANOIA_BENCH_OUT");
        if (outDir == null || outDir.isEmpty()) {
            throw new RuntimeException("PARANOIA_BENCH_OUT is not set");
        }
        long decompTimeout = 120;
        String t = System.getenv("PARANOIA_BENCH_DECOMP_TIMEOUT");
        if (t != null && !t.isEmpty()) {
            decompTimeout = Long.parseLong(t.trim());
        }
        // Sampling: the benchmark decompiles at most this many non-thunk
        // functions per binary (first N by address) and records the rest of the
        // listing without C so function-discovery metrics stay complete.
        // 0 / unset = decompile everything.
        long maxFuncs = 0;
        String mf = System.getenv("PARANOIA_BENCH_MAX_FUNCS");
        if (mf != null && !mf.isEmpty()) {
            maxFuncs = Long.parseLong(mf.trim());
        }

        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        SymbolTable symtab = currentProgram.getSymbolTable();

        String sha = currentProgram.getExecutableSHA256();
        String exePath = currentProgram.getExecutablePath();
        String programName = currentProgram.getName();
        File outFile = new File(outDir, (sha == null ? programName.replaceAll("[^A-Za-z0-9._-]", "_") : sha) + ".ghidra.jsonl");
        PrintWriter w = new PrintWriter(new FileWriter(outFile));

        int[] counts = new int[4]; // total, thunk, external, dumped
        long totalDecompMs = 0;
        int sampledNonThunk = 0;

        // Collect in address order (the FunctionManager iterator is ascending) so
        // "first N non-thunk functions" is deterministic.
        java.util.List<Function> allFunctions = new java.util.ArrayList<>();
        for (Function f : fm.getFunctions(true)) {
            allFunctions.add(f);
        }

        // Header line so the harness can join the dump with the corpus manifest by SHA-256.
        w.println("{\"kind\":\"header\",\"tool\":\"ghidra\",\"formatVersion\":1,"
                + "\"sha256\":" + (sha == null ? "null" : "\"" + esc(sha) + "\"") + ","
                + "\"programName\":\"" + esc(programName) + "\","
                + "\"executablePath\":\"" + esc(exePath == null ? "" : exePath) + "\","
                + "\"imageBase\":\"" + Long.toHexString(currentProgram.getImageBase().getOffset()) + "\","
                + "\"language\":\"" + esc(currentProgram.getLanguageID().toString()) + "\","
                + "\"compilerSpec\":\"" + esc(currentProgram.getCompilerSpec().getCompilerSpecID().toString()) + "\"}");

        DecompInterface ifc = new DecompInterface();
        if (!ifc.openProgram(currentProgram)) {
            throw new RuntimeException("could not open program in DecompInterface");
        }

        for (Function f : allFunctions) {
            if (monitor != null && monitor.isCancelled()) {
                break;
            }
            counts[0]++;
            Address entry = f.getEntryPoint();
            boolean thunk = f.isThunk();
            boolean external = f.isExternal();
            if (thunk) {
                counts[1]++;
            }
            if (external) {
                counts[2]++;
            }
            boolean sampled = true;
            if (maxFuncs > 0) {
                sampled = !thunk && !external && sampledNonThunk < maxFuncs;
            }
            if (sampled && !thunk && !external) {
                sampledNonThunk++;
            }
            String name = f.getName();
            long t0 = System.currentTimeMillis();
            String ctext = null;
            String err = null;
            try {
                DecompileResults res = sampled ? ifc.decompileFunction(f, (int) decompTimeout, monitor) : null;
                if (!sampled) {
                    // Listing-only record: no C requested for this function.
                } else if (res == null) {
                    err = "null decompile result";
                } else if (res.decompileCompleted()) {
                    if (res.getDecompiledFunction() != null) {
                        ctext = res.getDecompiledFunction().getC();
                    } else {
                        err = "no decompiled function";
                    }
                } else {
                    String m = res.getErrorMessage();
                    err = (m == null || m.isEmpty()) ? "decompile did not complete" : m;
                }
            } catch (Throwable e) {
                err = e.getClass().getSimpleName() + ": " + e.getMessage();
            }
            long decompMs = System.currentTimeMillis() - t0;
            totalDecompMs += decompMs;

            // Direct call targets: function entry when the reference resolves to a
            // function, otherwise the primary symbol name at the referenced address.
            Set<String> calls = new LinkedHashSet<>();
            InstructionIterator it = listing.getInstructions(f.getBody(), true);
            while (it.hasNext()) {
                Instruction insn = it.next();
                if (!insn.getFlowType().isCall()) {
                    continue;
                }
                for (Reference r : insn.getReferencesFrom()) {
                    Address to = r.getToAddress();
                    if (to == null) {
                        continue;
                    }
                    Function tf = fm.getFunctionAt(to);
                    if (tf != null) {
                        calls.add("{\"entry\":" + addrStr(tf.getEntryPoint()) + ",\"name\":\"" + esc(tf.getName()) + "\"}");
                        continue;
                    }
                    Symbol s = symtab.getPrimarySymbol(to);
                    if (s != null) {
                        calls.add("{\"entry\":null,\"name\":\"" + esc(s.getName()) + "\"}");
                    }
                }
            }

            StringBuilder sb = new StringBuilder(ctext == null ? 256 : ctext.length() + 512);
            sb.append("{\"kind\":\"function\",\"entry\":").append(addrStr(entry));
            sb.append(",\"name\":\"").append(esc(name)).append('"');
            sb.append(",\"thunk\":").append(thunk);
            sb.append(",\"external\":").append(external);
            sb.append(",\"sampled\":").append(sampled);
            sb.append(",\"decompMs\":").append(decompMs);
            sb.append(",\"c\":");
            if (ctext == null) {
                sb.append("null");
            } else {
                sb.append('"').append(esc(ctext)).append('"');
            }
            sb.append(",\"error\":");
            sb.append(err == null ? "null" : "\"" + esc(err) + "\"");
            sb.append(",\"calls\":[");
            boolean first = true;
            for (String cs : calls) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                sb.append(cs);
            }
            sb.append("]}");
            w.println(sb);
            counts[3]++;
        }
        w.close();
        ifc.dispose();

        java.io.FileWriter sum = new java.io.FileWriter(new File(outDir, (sha == null ? programName.replaceAll("[^A-Za-z0-9._-]", "_") : sha) + ".ghidra.summary"), true);
        sum.write("{\"kind\":\"summary\",\"sha256\":" + (sha == null ? "null" : "\"" + esc(sha) + "\"")
                + ",\"functions\":" + counts[0]
                + ",\"thunks\":" + counts[1]
                + ",\"externals\":" + counts[2]
                + ",\"dumped\":" + counts[3]
                + ",\"totalDecompMs\":" + totalDecompMs
                + ",\"imageBase\":\"" + Long.toHexString(currentProgram.getImageBase().getOffset()) + "\"}\n");
        sum.close();
        println("BENCH ghidra: " + programName + " functions=" + counts[0] + " sampled=" + sampledNonThunk + " dumped=" + counts[3]
                + " decompilMs=" + totalDecompMs);
    }
}
