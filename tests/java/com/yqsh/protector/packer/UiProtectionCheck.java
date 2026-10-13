package com.yqsh.protector.packer;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.immutable.instruction.*;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;
import java.io.IOException;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** java -ea 执行，不依赖设备或新增测试框架。 */
public final class UiProtectionCheck {
    public static void main(String[] args) throws Exception {
        Map<String, String> parents = Map.of("Ltest/Dialog;", UiCallsiteRewriter.DIALOG);
        var show = new ImmutableMethodReference("Ltest/Dialog;", "show", List.of(), "V");
        int[] counts = {0, 0};
        var virtual = new ImmutableInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 7, 0, 0, 0, 0, show);
        var rewritten = (ImmutableInstruction35c) UiCallsiteRewriter.rewriteInstruction(virtual, parents, counts);
        assert rewritten.getOpcode() == Opcode.INVOKE_STATIC && rewritten.getRegisterC() == 7;
        var target = (ImmutableMethodReference) rewritten.getReference();
        assert target.getDefiningClass().equals(UiCallsiteRewriter.BRIDGE);
        assert target.getParameterTypes().equals(List.of(UiCallsiteRewriter.DIALOG));
        var superCall = new ImmutableInstruction35c(Opcode.INVOKE_SUPER, 1, 7, 0, 0, 0, 0, show);
        assert UiCallsiteRewriter.rewriteInstruction(superCall, parents, counts) == superCall;
        var range = new ImmutableInstruction3rc(Opcode.INVOKE_VIRTUAL_RANGE, 24, 3,
                new ImmutableMethodReference(UiCallsiteRewriter.WINDOW, "setFlags", List.of("I", "I"), "V"));
        var rangeResult = (ImmutableInstruction3rc) UiCallsiteRewriter.rewriteInstruction(range, parents, counts);
        assert rangeResult.getOpcode() == Opcode.INVOKE_STATIC_RANGE && rangeResult.getStartRegister() == 24 && rangeResult.getRegisterCount() == 3;
        assert UiCallsiteRewriter.bridgeOwner(new ImmutableMethodReference("Ltest/Other;", "show", List.of(), "V"), parents) == null;
        assert "Landroid/app/AlertDialog$Builder;".equals(UiCallsiteRewriter.bridgeOwner(new ImmutableMethodReference("Landroid/app/AlertDialog$Builder;", "show", List.of(), "Landroid/app/AlertDialog;"), parents));
        for (boolean utf8 : new boolean[]{true, false}) {
            byte[] data = table(utf8);
            byte[] before = data.clone();
            var result = ResourceNameObfuscator.rewrite(data, Set.of("kept_action"));
            assert result.changed == 1 && result.kept == 2;
            int keyOffset = 12 + 288 + pool(List.of("id", "string"), utf8).length;
            var keys = ResPathObfuscator.StringPool.parse(data, keyOffset);
            assert keys.readString(0).equals("ua");
            assert keys.readString(1).equals("kept_action") && keys.readString(2).equals("shared");
            assert (ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).getInt(keyOffset + 16) & 1) == 0;
            assert data.length == before.length;
            int keyEnd = keyOffset + ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).getInt(keyOffset + 4);
            assert Arrays.equals(Arrays.copyOfRange(before, keyEnd, before.length), Arrays.copyOfRange(data, keyEnd, data.length));
            byte[] aliased = table(utf8);
            ByteBuffer ab = ByteBuffer.wrap(aliased).order(ByteOrder.LITTLE_ENDIAN);
            ab.putInt(keyOffset + 28 + 4, ab.getInt(keyOffset + 28));
            assert ResourceNameObfuscator.rewrite(aliased, Set.of()).changed == 0;
            byte[] duplicateNames = table(utf8);
            ResPathObfuscator.StringPool.parse(duplicateNames, keyOffset).replaceString(0, "kept_action");
            assert ResourceNameObfuscator.rewrite(duplicateNames, Set.of()).changed == 0;
            byte[] malformed = table(utf8);
            ByteBuffer.wrap(malformed).order(ByteOrder.LITTLE_ENDIAN).putInt(keyOffset + 28, Integer.MAX_VALUE);
            try { ResourceNameObfuscator.rewrite(malformed, Set.of()); throw new AssertionError("未拒绝越界偏移"); } catch (IOException expected) { }
            byte[] sparse = table(utf8); sparse[keyEnd + 9] = 1;
            assert ResourceNameObfuscator.rewrite(sparse, Set.of()).unsupportedPackages == 1;
        }
        System.out.println("窗口虚分派、寄存器、资源 ID/值保留、UTF-8/16、共享 key、偏移别名、越界、稀疏表检查通过");
    }

    private static byte[] table(boolean utf8) {
        byte[] types = pool(List.of("id", "string"), utf8), keys = pool(List.of("sensitive_action", "kept_action", "shared"), utf8);
        byte[] ids = type(1, new int[]{0, 1, 2}), strings = type(2, new int[]{2});
        int size = 288 + types.length + keys.length + ids.length + strings.length;
        ByteBuffer b = ByteBuffer.allocate(12 + size).order(ByteOrder.LITTLE_ENDIAN);
        b.putShort((short)2).putShort((short)12).putInt(b.capacity()).putInt(1);
        b.putShort((short)0x200).putShort((short)288).putInt(size).putInt(0x7f);
        b.putInt(12 + 268, 288); b.putInt(12 + 276, 288 + types.length);
        b.position(12 + 288); b.put(types).put(keys).put(ids).put(strings);
        return b.array();
    }
    private static byte[] type(int id, int[] keys) {
        int start = 24 + keys.length * 4;
        ByteBuffer b = ByteBuffer.allocate(start + keys.length * 16).order(ByteOrder.LITTLE_ENDIAN);
        b.putShort((short)0x201).putShort((short)24).putInt(b.capacity()).put((byte)id).put((byte)0).putShort((short)0).putInt(keys.length).putInt(start).putInt(4);
        for (int i = 0; i < keys.length; i++) b.putInt(i * 16);
        for (int key : keys) b.putShort((short)8).putShort((short)0).putInt(key).putShort((short)8).put((byte)0).put((byte)0x10).putInt(1);
        return b.array();
    }
    private static byte[] pool(List<String> strings, boolean utf8) {
        int bytes = strings.stream().mapToInt(s -> utf8 ? s.length() + 3 : s.length() * 2 + 4).sum();
        int start = 28 + strings.size() * 4;
        ByteBuffer b = ByteBuffer.allocate((start + bytes + 3) & ~3).order(ByteOrder.LITTLE_ENDIAN);
        b.putShort((short)1).putShort((short)28).putInt(b.capacity()).putInt(strings.size()).putInt(0).putInt((utf8 ? 256 : 0) | 1).putInt(start).putInt(0);
        int offset = 0;
        for (String s : strings) { b.putInt(offset); offset += utf8 ? s.length() + 3 : s.length() * 2 + 4; }
        for (String s : strings) {
            if (utf8) b.put((byte)s.length()).put((byte)s.length()).put(s.getBytes(StandardCharsets.UTF_8)).put((byte)0);
            else b.putShort((short)s.length()).put(s.getBytes(StandardCharsets.UTF_16LE)).putShort((short)0);
        }
        return b.array();
    }
}
