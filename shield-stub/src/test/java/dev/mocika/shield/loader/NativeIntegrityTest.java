package dev.mocika.shield.loader;

import org.junit.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class NativeIntegrityTest {

    @Test
    public void 按当前_ABI_取出对应摘要() {
        String raw = "arm64-v8a:aabb,armeabi-v7a:ccdd";
        assertEquals("aabb", NativeIntegrity.selectAbiDigest(raw, "arm64-v8a"));
        assertEquals("ccdd", NativeIntegrity.selectAbiDigest(raw, "armeabi-v7a"));
    }

    @Test
    public void 缺失字段与未知_ABI_返回_null() {
        assertNull(NativeIntegrity.selectAbiDigest(null, "arm64-v8a"));
        assertNull(NativeIntegrity.selectAbiDigest("arm64-v8a:aabb", null));
        assertNull(NativeIntegrity.selectAbiDigest("arm64-v8a:aabb", "x86_64"));
        // 空值不应被当作有效摘要
        assertNull(NativeIntegrity.selectAbiDigest("arm64-v8a:", "arm64-v8a"));
        // 破损条目跳过而不是抛异常
        assertNull(NativeIntegrity.selectAbiDigest("nocolon,arm64-v8a:aabb", "x86"));
    }

    @Test
    public void 按设备_ABI_优先级选取摘要() {
        String raw = "arm64-v8a:aabb,armeabi-v7a:ccdd";
        // 设备支持多种 ABI 时取第一个有摘要的
        assertEquals("aabb", NativeIntegrity.selectDeviceAbiDigest(
                raw, new String[]{"arm64-v8a", "armeabi-v7a"}));
        // 32 位包在 64 位设备上：设备首选 arm64 但包内只有 v7a，
        // 应回落到 v7a 而不是判定缺失
        assertEquals("ccdd", NativeIntegrity.selectDeviceAbiDigest(
                "armeabi-v7a:ccdd", new String[]{"arm64-v8a", "armeabi-v7a", "armeabi"}));
        // 都不匹配时返回 null 而不是抛异常
        assertNull(NativeIntegrity.selectDeviceAbiDigest(raw, new String[]{"x86_64"}));
        assertNull(NativeIntegrity.selectDeviceAbiDigest(null, new String[]{"arm64-v8a"}));
        assertNull(NativeIntegrity.selectDeviceAbiDigest(raw, null));
    }

    @Test
    public void 只识别壳库别名形状的条目() {
        // 16 位小写字母别名，符合壳库命名
        assertTrue(NativeIntegrity.isShellLibraryEntry(
                "lib/arm64-v8a/libmodulecorebridge.so", "lib/arm64-v8a/"));
        // 业务库保留原名称，长度与字符集都不匹配
        assertFalse(NativeIntegrity.isShellLibraryEntry(
                "lib/arm64-v8a/libbusiness.so", "lib/arm64-v8a/"));
        // 大写字母不符合别名生成规则
        assertFalse(NativeIntegrity.isShellLibraryEntry(
                "lib/arm64-v8a/libModuleCorebridge.so", "lib/arm64-v8a/"));
        // 其他 ABI 与子目录不应命中
        assertFalse(NativeIntegrity.isShellLibraryEntry(
                "lib/armeabi-v7a/libmodulecorebridge.so", "lib/arm64-v8a/"));
        assertFalse(NativeIntegrity.isShellLibraryEntry(
                "lib/arm64-v8a/sub/libmodulecorebridge.so", "lib/arm64-v8a/"));
        // 非库文件
        assertFalse(NativeIntegrity.isShellLibraryEntry(
                "lib/arm64-v8a/classes.dex", "lib/arm64-v8a/"));
    }

    @Test
    public void 解压目录只识别壳库文件名() {
        assertTrue(NativeIntegrity.isShellLibraryFileName("libmoduleapisupport.so"));
        assertFalse(NativeIntegrity.isShellLibraryFileName("libbusiness.so"));
        assertFalse(NativeIntegrity.isShellLibraryFileName("lib/arm64-v8a/libmoduleapisupport.so"));
        assertFalse(NativeIntegrity.isShellLibraryFileName("libModuleapisupport.so"));
    }

    @Test
    public void 解压副本按实际文件字节计算摘要() throws Exception {
        File directory = Files.createTempDirectory("native-integrity").toFile();
        try {
            Files.write(new File(directory, "libmoduleapisupport.so").toPath(),
                    "payload".getBytes(StandardCharsets.UTF_8));
            assertEquals("239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5",
                    NativeIntegrity.hashExtractedShellLibrary(directory.getPath()));
        } finally {
            Files.deleteIfExists(new File(directory, "libmoduleapisupport.so").toPath());
            Files.deleteIfExists(directory.toPath());
        }
    }

    @Test
    public void 解压目录缺少唯一壳库时返回_null() throws Exception {
        File directory = Files.createTempDirectory("native-integrity-empty").toFile();
        try {
            assertNull(NativeIntegrity.hashExtractedShellLibrary(directory.getPath()));
        } finally {
            Files.deleteIfExists(directory.toPath());
        }
    }
}
