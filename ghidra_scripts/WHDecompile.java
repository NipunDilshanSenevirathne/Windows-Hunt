// WHDecompile.java — headless decompilation of the functions Windows Hunt flagged.
//
// Invoked by scripts/ghidra_decompile.py. Reads a newline-separated list of targets from the
// script arguments: either a function name, an address (0x...), or an imported API name
// prefixed with "api:" (decompiles every function that CALLS it — the callers are where the
// argument comes from, which is what you actually need to read).
//
// Writes one .c file per function plus an index, into the output directory.
//@category WindowsHunt
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import java.io.*;
import java.util.*;

public class WHDecompile extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) { println("usage: WHDecompile <outdir> <target[,target...]>"); return; }
        File outDir = new File(args[0]);
        outDir.mkdirs();
        Set<String> targets = new LinkedHashSet<>(Arrays.asList(args[1].split(",")));

        DecompInterface d = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        d.setOptions(opts);
        d.openProgram(currentProgram);

        FunctionManager fm = currentProgram.getFunctionManager();
        Set<Function> wanted = new LinkedHashSet<>();

        for (String t : targets) {
            t = t.trim();
            if (t.isEmpty()) continue;
            if (t.startsWith("api:")) {
                String api = t.substring(4);
                // every reference to a symbol whose name contains the API -> the calling function
                SymbolTable st = currentProgram.getSymbolTable();
                SymbolIterator it = st.getAllSymbols(true);
                while (it.hasNext()) {
                    Symbol s = it.next();
                    if (!s.getName().toLowerCase().contains(api.toLowerCase())) continue;
                    for (Reference r : s.getReferences()) {
                        Function f = fm.getFunctionContaining(r.getFromAddress());
                        if (f != null) wanted.add(f);
                    }
                }
            } else if (t.startsWith("0x") || t.matches("[0-9a-fA-F]{6,16}")) {
                Address a = currentProgram.getAddressFactory().getAddress(t.replace("0x", ""));
                Function f = fm.getFunctionContaining(a);
                if (f != null) wanted.add(f);
            } else {
                for (Function f : fm.getFunctions(true)) {
                    if (f.getName().equalsIgnoreCase(t) || f.getName().contains(t)) wanted.add(f);
                }
            }
        }

        PrintWriter idx = new PrintWriter(new File(outDir, "_index.txt"));
        int n = 0;
        for (Function f : wanted) {
            if (n >= 80) break;                       // keep headless runs bounded
            DecompileResults res = d.decompileFunction(f, 90, monitor);
            if (res == null || !res.decompileCompleted()) continue;
            String code = res.getDecompiledFunction().getC();
            String name = f.getName().replaceAll("[^A-Za-z0-9_.]", "_");
            File out = new File(outDir, name + "_" + f.getEntryPoint() + ".c");
            try (PrintWriter pw = new PrintWriter(out)) {
                pw.println("// " + currentProgram.getName() + "  " + f.getName()
                           + " @ " + f.getEntryPoint());
                pw.println("// callers: " + f.getCallingFunctions(monitor).size()
                           + "  callees: " + f.getCalledFunctions(monitor).size());
                pw.println(code);
            }
            idx.println(f.getEntryPoint() + "\t" + f.getName() + "\t" + out.getName());
            n++;
        }
        idx.close();
        println("WHDecompile: wrote " + n + " functions to " + outDir);
        d.dispose();
    }
}
