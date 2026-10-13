package com.yqsh.protector.packer;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

/** 仅改写 id 独占的 key；保留数值 ID、类型表、资源值和所有文件路径。 */
final class ResourceNameObfuscator {
    static final class Result {
        int changed;
        int kept;
        int unsupportedPackages;
    }

    static Result rewrite(byte[] data, Set<String> keep) throws IOException {
        Result result = new Result();
        ByteBuffer b = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        int end = chunk(b, 0, data.length);
        if (u16(b, 0) != 2 || u16(b, 2) < 12 || end != data.length) throw new IOException("资源表头无效");
        for (int p = u16(b, 2); p < end;) {
            int next = chunk(b, p, end);
            if (u16(b, p) == 0x200) rewritePackage(data, b, p, next, keep, result);
            p = next;
        }
        return result;
    }

    private static void rewritePackage(byte[] data, ByteBuffer b, int p, int end, Set<String> keep, Result result) throws IOException {
        int header = u16(b, p + 2);
        if (header < 284) throw new IOException("资源包头过短");
        int typesOffset = b.getInt(p + 268), keysOffset = b.getInt(p + 276);
        if (typesOffset < header || keysOffset < header || typesOffset >= end - p || keysOffset >= end - p) throw new IOException("资源池偏移越界");
        var types = pool(data, b, p + typesOffset, end);
        var keys = pool(data, b, p + keysOffset, end);
        if (keys.styleCount != 0 || (header >= 288 && b.getInt(p + 284) != 0)) { result.unsupportedPackages++; return; }
        Set<Integer> ids = new HashSet<>(), other = new HashSet<>();
        boolean unsupported = false;
        for (int c = p + header; c < end;) {
            int next = chunk(b, c, end), kind = u16(b, c);
            if (kind == 0x201) {
                int h = u16(b, c + 2);
                if (h < 20) throw new IOException("资源类型头过短");
                int type = b.get(c + 8) & 255, flags = b.get(c + 9) & 255;
                if (type == 0 || type > types.stringCount) throw new IOException("资源类型索引越界");
                if (flags != 0) { unsupported = true; c = next; continue; }
                int count = b.getInt(c + 12), start = b.getInt(c + 16);
                if (count < 0 || start < h || (long) h + count * 4L > start || start > next - c) throw new IOException("资源条目表越界");
                for (int i = 0; i < count; i++) {
                    int offset = b.getInt(c + h + i * 4);
                    if (offset == -1) continue;
                    if (offset < 0 || (long) start + offset + 8 > next - c) throw new IOException("资源条目偏移越界");
                    int e = c + start + offset;
                    if ((u16(b, e + 2) & 8) != 0) { unsupported = true; continue; }
                    if (u16(b, e) < 8 || (long) e + u16(b, e) > next) throw new IOException("资源条目头无效");
                    int key = b.getInt(e + 4);
                    if (key < 0 || key >= keys.stringCount) throw new IOException("资源名称索引越界");
                    ("id".equals(types.readString(type - 1)) ? ids : other).add(key);
                }
            } else if (kind != 1 && kind != 0x202) {
                // ponytail: 动态库、overlay/未知块可能按名称链接；有明确引用模型后再放开。
                unsupported = true;
            }
            c = next;
        }
        if (unsupported) { result.unsupportedPackages++; return; }
        Map<Integer, Integer> offsetUses = new HashMap<>();
        Map<String, Integer> nameUses = new HashMap<>();
        Set<String> occupied = new HashSet<>(keep);
        for (int i = 0; i < keys.stringCount; i++) {
            offsetUses.merge(keys.offsets[i], 1, Integer::sum);
            nameUses.merge(keys.readString(i), 1, Integer::sum);
            occupied.add(keys.readString(i));
        }
        ResPathObfuscator.ShortNameGen gen = new ResPathObfuscator.ShortNameGen();
        int changedBefore = result.changed;
        for (int i : new TreeSet<>(ids)) {
            String old = keys.readString(i);
            if (other.contains(i) || keep.contains(old) || offsetUses.get(keys.offsets[i]) > 1 || nameUses.get(old) > 1 || !old.matches("[a-zA-Z_][a-zA-Z0-9_]*")) { result.kept++; continue; }
            String name;
            do { name = "u" + gen.next(); } while (!occupied.add(name));
            if (!keys.canReplace(i, name)) { result.kept++; continue; }
            keys.replaceString(i, name);
            result.changed++;
        }
        if (result.changed > changedBefore) b.putInt(keys.chunkOffset + 16, b.getInt(keys.chunkOffset + 16) & ~1);
    }

    static int chunk(ByteBuffer b, int p, int limit) throws IOException {
        if (p < 0 || p > limit - 8) throw new IOException("资源块头越界");
        int header = u16(b, p + 2), size = b.getInt(p + 4);
        if (header < 8 || size < header || size > limit - p) throw new IOException("资源块大小无效");
        return p + size;
    }

    private static ResPathObfuscator.StringPool pool(byte[] data, ByteBuffer b, int p, int limit) throws IOException {
        int end = chunk(b, p, limit), h = u16(b, p + 2);
        if (u16(b, p) != 1 || h < 28) throw new IOException("缺少字符串池");
        int count = b.getInt(p + 8), styles = b.getInt(p + 12), start = b.getInt(p + 20), styleStart = b.getInt(p + 24);
        if (count < 0 || styles < 0 || (long) h + ((long) count + styles) * 4 > start || start > end - p ||
                (styles > 0 && (styleStart < start || styleStart > end - p))) throw new IOException("字符串池索引越界");
        var pool = ResPathObfuscator.StringPool.parse(data, p);
        TreeSet<Integer> offsets = new TreeSet<>();
        for (int o : pool.offsets) {
            if (o < pool.stringsStart || o >= pool.stringDataEnd) throw new IOException("字符串偏移越界");
            offsets.add(o);
        }
        // 校验完整编码与终止符，拒绝重叠字符串，避免原地替换破坏相邻条目。
        for (int o : offsets) {
            int stop = offsets.higher(o) == null ? pool.stringDataEnd : offsets.higher(o);
            ByteBuffer s = ByteBuffer.wrap(data, o, stop - o).slice().order(ByteOrder.LITTLE_ENDIAN);
            try {
                int length;
                if (pool.utf8) { readLength(s, true); length = readLength(s, true); }
                else { length = Math.multiplyExact(readLength(s, false), 2); }
                int terminator = pool.utf8 ? 1 : 2;
                if (length < 0 || length > s.remaining() - terminator) throw new IOException("字符串内容越界");
                s.position(s.position() + length);
                if (s.get() != 0 || (!pool.utf8 && s.get() != 0)) throw new IOException("字符串缺少终止符");
            } catch (java.nio.BufferUnderflowException | ArithmeticException e) { throw new IOException("字符串长度无效", e); }
        }
        return pool;
    }

    private static int readLength(ByteBuffer b, boolean utf8) {
        int n = utf8 ? b.get() & 255 : b.getShort() & 65535;
        int high = utf8 ? 128 : 32768;
        return (n & high) == 0 ? n : ((n & (high - 1)) << (utf8 ? 8 : 16)) | (utf8 ? b.get() & 255 : b.getShort() & 65535);
    }
    private static int u16(ByteBuffer b, int p) { return b.getShort(p) & 65535; }
}
