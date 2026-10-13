package com.yqsh.protector.packer;

import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction;
import com.android.tools.smali.dexlib2.iface.reference.StringReference;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;

/** 独立于 PVM2 开关的界面改写入口；报告无原名映射，不写入业务 APK。 */
final class UiProtectionTool {
    static void run(String[] args) throws Exception {
        Map<String, String> options = new HashMap<>();
        for (int i = 1; i < args.length; i += 2) {
            if (i + 1 == args.length || !Set.of("--dir", "--external-dex", "--input", "--output", "--source", "--keep", "--report").contains(args[i]) || options.put(args[i], args[i + 1]) != null) throw new IOException("界面改写参数无效");
        }
        Path report = Path.of(required(options, "--report"));
        if ("ui-transform".equals(args[0])) {
            List<Path> files;
            try (var paths = Files.list(Path.of(required(options, "--dir")))) {
                files = new ArrayList<>(paths.filter(p -> p.getFileName().toString().matches("classes(?:[2-9]|[1-9][0-9]+)?\\.dex")).sorted().toList());
            }
            if (options.containsKey("--external-dex")) try (var paths = Files.walk(Path.of(options.get("--external-dex")))) {
                files.addAll(paths.filter(p -> Files.isRegularFile(p) && p.toString().endsWith(".dex")).sorted().toList());
            }
            if (files.isEmpty()) throw new IOException("未找到可改写的 DEX");
            int[] counts = UiCallsiteRewriter.rewrite(files);
            Files.writeString(report, "{\"version\":1,\"rewritten\":" + counts[0] + ",\"unresolved\":" + counts[1] + "}");
        } else {
            Set<String> keep = new HashSet<>(Arrays.asList(options.getOrDefault("--keep", "").split(",")));
            String reason = inspectSource(Path.of(required(options, "--source")), keep);
            Path input = Path.of(required(options, "--input")), output = Path.of(required(options, "--output"));
            if (input.toAbsolutePath().normalize().equals(output.toAbsolutePath().normalize())) throw new IOException("资源改写输入输出必须不同");
            ResourceNameObfuscator.Result result = new ResourceNameObfuscator.Result();
            try (ZipFile zip = new ZipFile(input.toFile())) {
                ZipEntry arsc = zip.getEntry("resources.arsc");
                if (arsc == null) reason = "no_resource_table";
                if (!reason.isEmpty()) Files.copy(input, output, StandardCopyOption.REPLACE_EXISTING);
                else {
                    byte[] data;
                    try (InputStream in = zip.getInputStream(arsc)) { data = in.readAllBytes(); }
                    result = ResourceNameObfuscator.rewrite(data, keep);
                    try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(output))) {
                        var entries = zip.entries();
                        while (entries.hasMoreElements()) {
                            ZipEntry e = entries.nextElement(), copy = new ZipEntry(e);
                            boolean table = e.getName().equals("resources.arsc");
                            if (table) {
                                CRC32 crc = new CRC32(); crc.update(data);
                                copy.setMethod(ZipEntry.STORED); copy.setSize(data.length); copy.setCompressedSize(data.length); copy.setCrc(crc.getValue());
                            } else if (copy.getMethod() == ZipEntry.DEFLATED) copy.setCompressedSize(-1);
                            out.putNextEntry(copy);
                            if (table) out.write(data);
                            else try (InputStream in = zip.getInputStream(e)) { in.transferTo(out); }
                            out.closeEntry();
                        }
                    }
                }
            }
            Files.writeString(report, "{\"version\":1,\"renamed\":" + result.changed + ",\"kept\":" + result.kept + ",\"unsupported_packages\":" + result.unsupportedPackages + ",\"skip_reason\":\"" + reason + "\"}");
        }
    }

    static String inspectSource(Path source, Set<String> keep) throws IOException {
        String reason = "";
        try (ZipFile zip = new ZipFile(source.toFile())) {
            var entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
                String name = e.getName().toLowerCase(Locale.ROOT);
                // ponytail: 无法证明 Native/脚本的动态查名范围，整包保留；后续有引用清单再缩小范围。
                if (!e.isDirectory() && (name.endsWith(".so") || name.startsWith("assets/"))) reason = "opaque_native_or_assets";
                if (!name.matches("classes(?:[2-9]|[1-9][0-9]+)?\\.dex")) continue;
                DexBackedDexFile dex;
                try (var in = new BufferedInputStream(zip.getInputStream(e))) { dex = DexBackedDexFile.fromInputStream(Opcodes.getDefault(), in); }
                for (String s : dex.getStringSection()) if (Set.of("getIdentifier", "getResourceEntryName", "getResourceName", "loadDex", "DexClassLoader", "InMemoryDexClassLoader").contains(s) || s.contains("DexClassLoader;")) reason = "dynamic_resource_lookup";
                // 只保留实际字符串常量；R.id 的字段名属于结构元数据，不是按名称读取。
                for (var cls : dex.getClasses()) for (var method : cls.getMethods()) {
                    if (method.getImplementation() == null) continue;
                    for (var instruction : method.getImplementation().getInstructions()) {
                        if (instruction instanceof ReferenceInstruction ref && ref.getReference() instanceof StringReference s) keep.add(s.getString());
                    }
                }
            }
        }
        return reason;
    }
    private static String required(Map<String, String> options, String key) throws IOException {
        String value = options.get(key);
        if (value == null || value.isEmpty()) throw new IOException("缺少参数 " + key);
        return value;
    }
}
