package com.yqsh.protector.packer;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction35c;
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction3rc;
import com.android.tools.smali.dexlib2.iface.reference.MethodReference;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction35c;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction3rc;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile;
import com.android.tools.smali.dexlib2.rewriter.*;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;
import java.io.*;
import java.nio.file.*;
import java.util.*;

/** 保留接收者寄存器与虚分派，仅改写已知 Dialog/Window 的虚调用。 */
final class UiCallsiteRewriter {
    static final String BRIDGE = "Ldev/mocika/shield/loader/MocikaUi;";
    static final String DIALOG = "Landroid/app/Dialog;";
    static final String WINDOW = "Landroid/view/Window;";

    static DexBackedDexFile read(Path file) throws IOException {
        try (var input = new BufferedInputStream(Files.newInputStream(file))) {
            return DexBackedDexFile.fromInputStream(Opcodes.getDefault(), input);
        }
    }

    static int[] rewrite(List<Path> files) throws IOException {
        Map<String, String> parents = new HashMap<>();
        for (Path file : files) for (ClassDef cls : read(file).getClasses()) {
            if (BRIDGE.equals(cls.getType())) throw new IOException("输入 DEX 已占用界面保护桥类");
            parents.put(cls.getType(), cls.getSuperclass());
        }
        // SDK 类不随业务打包；这些已知平台子类可直接确认，第三方子类沿输入 DEX 解析。
        for (String name : List.of("AlertDialog", "ProgressDialog", "DatePickerDialog", "TimePickerDialog", "Presentation")) {
            parents.put("Landroid/app/" + name + ";", DIALOG);
        }
        int[] counts = new int[2];
        for (Path file : files) {
            int before = counts[0];
            var rewritten = ImmutableDexFile.of(new DexRewriter(new RewriterModule() {
                @Override public Rewriter<Instruction> getInstructionRewriter(Rewriters rewriters) {
                    return instruction -> rewriteInstruction(instruction, parents, counts);
                }
            }).getDexFileRewriter().rewrite(read(file)));
            DexPool pool = new DexPool(Opcodes.getDefault());
            for (ClassDef cls : rewritten.getClasses()) pool.internClass(cls);
            if (counts[0] == before) continue;
            Path temp = Files.createTempFile(file.getParent(), "ui-", ".dex");
            try {
                var output = new FileDataStore(temp.toFile());
                try { pool.writeTo(output); } finally { output.close(); }
                Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
            } finally { Files.deleteIfExists(temp); }
        }
        return counts;
    }

    static Instruction rewriteInstruction(Instruction instruction, Map<String, String> parents, int[] counts) {
        // invoke-super 必须保留原分派，否则 Dialog 子类的 super.show() 会递归。
        if (instruction.getOpcode() != Opcode.INVOKE_VIRTUAL && instruction.getOpcode() != Opcode.INVOKE_VIRTUAL_RANGE) return instruction;
        MethodReference method;
        if (instruction instanceof Instruction35c i && i.getReference() instanceof MethodReference m) method = m;
        else if (instruction instanceof Instruction3rc i && i.getReference() instanceof MethodReference m) method = m;
        else return instruction;
        String owner = bridgeOwner(method, parents);
        if (owner == null) {
            if (Set.of("show", "clearFlags", "setFlags", "setAttributes").contains(method.getName())) counts[1]++;
            return instruction;
        }
        List<String> params = new ArrayList<>();
        params.add(owner);
        for (CharSequence p : method.getParameterTypes()) params.add(p.toString());
        var target = new ImmutableMethodReference(BRIDGE, method.getName(), params, method.getReturnType());
        counts[0]++;
        if (instruction instanceof Instruction35c i) return new ImmutableInstruction35c(Opcode.INVOKE_STATIC,
                i.getRegisterCount(), i.getRegisterC(), i.getRegisterD(), i.getRegisterE(), i.getRegisterF(), i.getRegisterG(), target);
        Instruction3rc i = (Instruction3rc) instruction;
        return new ImmutableInstruction3rc(Opcode.INVOKE_STATIC_RANGE, i.getStartRegister(), i.getRegisterCount(), target);
    }

    static String bridgeOwner(MethodReference m, Map<String, String> parents) {
        List<String> p = m.getParameterTypes().stream().map(Object::toString).toList();
        boolean builder = "show".equals(m.getName()) && p.isEmpty() && "Landroid/app/AlertDialog;".equals(m.getReturnType());
        if (!builder && !"V".equals(m.getReturnType())) return null;
        String base = builder ? "Landroid/app/AlertDialog$Builder;" : "show".equals(m.getName()) && p.isEmpty() ? DIALOG :
                ("clearFlags".equals(m.getName()) && p.equals(List.of("I"))) ||
                ("setFlags".equals(m.getName()) && p.equals(List.of("I", "I"))) ||
                ("setAttributes".equals(m.getName()) && p.equals(List.of("Landroid/view/WindowManager$LayoutParams;"))) ? WINDOW : null;
        Set<String> seen = new HashSet<>();
        for (String c = m.getDefiningClass(); c != null && seen.add(c); c = parents.get(c)) {
            if (c.equals(base)) return base;
        }
        return null;
    }
}
