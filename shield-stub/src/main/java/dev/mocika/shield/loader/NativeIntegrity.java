package dev.mocika.shield.loader;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Log;

import dev.mocika.shield.stub.BuildConfig;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 壳原生库的启动期完整性校验。
 *
 * 打包时按 ABI 记录壳库明文 SHA-256 并写入 manifest；此处按系统实际的
 * Native 库加载策略计算摘要：解压模式校验 {@code nativeLibraryDir} 中即将加载的
 * 文件，直接映射模式校验 APK 内对应条目。壳库在打包流程中只改文件名、不改字节，
 * 因此构建期摘要与运行期字节一致。
 *
 * <p>该检查只提高替换壳库的成本，不构成机密性保证：能改写 APK 的攻击者同样
 * 能改写 manifest 中的摘要值。Release 默认开启、Debug 默认关闭，见
 * {@link BuildConfig#NATIVE_SELF_CHECK}。
 */
final class NativeIntegrity {

    private static final String TAG = "NativeIntegrity";
    private static final String FIELD = "dev.mocika.shield.NATIVE_INTEGRITY";
    /** 壳库别名形如 lib[a-z]{16}.so，业务库使用其真实名称，据此区分。 */
    private static final int ALIAS_BODY_LENGTH = 16;

    private NativeIntegrity() {
    }

    /**
     * 校验当前设备 ABI 下的壳库摘要。
     *
     * <p>开关关闭时直接返回；开关开启但缺少完整性字段或实际库时失败关闭。
     *
     * @throws SecurityException 摘要不一致（仅开关开启时抛出）
     */
    static void verify(Context context) throws Exception {
        if (!BuildConfig.NATIVE_SELF_CHECK) return;
        String expected = readExpectedDigest(context);
        if (expected == null) throw new SecurityException("N70");
        String actual = readInstalledDigest(context);
        if (actual == null) throw new SecurityException("N71");
        if (!expected.equalsIgnoreCase(actual)) {
            throw new SecurityException("N72");
        }
        if (BuildConfig.DEBUG_LOGS) Log.d(TAG, "native integrity ok");
    }

    /** 读取 manifest 中当前 ABI 的期望摘要，未配置返回 null。 */
    private static String readExpectedDigest(Context context) {
        try {
            ApplicationInfo info = context.getPackageManager().getApplicationInfo(
                    context.getPackageName(), PackageManager.GET_META_DATA);
            if (info.metaData == null) return null;
            String raw = info.metaData.getString(FIELD);
            return selectDeviceAbiDigest(raw, Build.SUPPORTED_ABIS);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 按设备 ABI 优先级取出可用摘要。
     *
     * <p>不能用 {@code SUPPORTED_ABIS[0]}：仅含 32 位库的应用在 64 位设备上运行时，
     * 设备首选 ABI 是 arm64-v8a，而包内只有 armeabi-v7a，会误判为缺失。
     * 这里按设备顺序找到第一个包内确实提供了壳库的 ABI，与 Android 的库选择规则一致。
     */
    static String selectDeviceAbiDigest(String raw, String[] supportedAbis) {
        if (raw == null || supportedAbis == null) return null;
        for (String abi : supportedAbis) {
            String digest = selectAbiDigest(raw, abi);
            if (digest != null) return digest;
        }
        return null;
    }

    /**
     * 从 `abi:hex,abi:hex` 形式的值中取出指定 ABI 的摘要。
     * 拆为独立方法以便单元测试覆盖解析逻辑。
     */
    static String selectAbiDigest(String raw, String abi) {
        if (raw == null || abi == null) return null;
        for (String part : raw.split(",")) {
            int colon = part.indexOf(':');
            if (colon <= 0) continue;
            if (part.substring(0, colon).equals(abi)) {
                String digest = part.substring(colon + 1).trim();
                return digest.isEmpty() ? null : digest;
            }
        }
        return null;
    }

    /**
     * 按系统实际加载策略计算壳库 SHA-256（小写十六进制）。
     *
     * <p>{@link ApplicationInfo#FLAG_EXTRACT_NATIVE_LIBS} 开启时，系统从
     * {@code nativeLibraryDir} 加载解压副本；否则直接从 APK 映射库文件。不能在
     * 解压模式下回退到 APK 条目，否则替换解压副本仍会绕过校验。
     */
    private static String readInstalledDigest(Context context) throws Exception {
        ApplicationInfo info = context.getApplicationInfo();
        if ((info.flags & ApplicationInfo.FLAG_EXTRACT_NATIVE_LIBS) != 0) {
            return hashExtractedShellLibrary(info.nativeLibraryDir);
        }
        return hashApkShellLibrary(info.sourceDir);
    }

    /** 计算解压模式下系统即将加载的壳库副本。 */
    static String hashExtractedShellLibrary(String directoryPath) throws Exception {
        if (directoryPath == null || directoryPath.isEmpty()) return null;
        File directory = new File(directoryPath);
        File[] candidates = directory.listFiles(
                file -> file.isFile() && isShellLibraryFileName(file.getName()));
        if (candidates == null || candidates.length != 1) return null;
        return hashFile(candidates[0]);
    }

    /** 计算直接映射模式下 APK 内壳库条目。 */
    private static String hashApkShellLibrary(String apkPath) throws Exception {
        if (apkPath == null || apkPath.isEmpty()) return null;
        String[] abis = Build.SUPPORTED_ABIS;
        if (abis == null || abis.length == 0) return null;
        try (ZipFile zip = new ZipFile(apkPath)) {
            for (String abi : abis) {
                String prefix = "lib/" + abi + "/";
                String digest = hashShellLibrary(zip, prefix);
                if (digest != null) return digest;
            }
        }
        return null;
    }

    /** 计算指定 ABI 目录下壳库条目的 SHA-256，未找到返回 null。 */
    private static String hashShellLibrary(ZipFile zip, String prefix) throws Exception {
        java.util.Enumeration<? extends ZipEntry> entries = zip.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            if (!isShellLibraryEntry(entry.getName(), prefix)) continue;
            try (InputStream is = zip.getInputStream(entry)) {
                return hashStream(is);
            }
        }
        return null;
    }

    private static String hashFile(File file) throws Exception {
        try (InputStream input = new FileInputStream(file)) {
            return hashStream(input);
        }
    }

    private static String hashStream(InputStream input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[8192];
        int read;
        while ((read = input.read(buffer)) != -1) {
            digest.update(buffer, 0, read);
        }
        return toHex(digest.digest());
    }

    /** 判断文件名是否符合任务级壳库别名形状。 */
    static boolean isShellLibraryFileName(String fileName) {
        return isShellLibraryEntry(fileName, "");
    }

    /** 判断条目是否为指定 ABI 下的壳库（lib&lt;16位小写字母&gt;.so）。 */
    static boolean isShellLibraryEntry(String entryName, String abiPrefix) {
        if (entryName == null || !entryName.startsWith(abiPrefix)) return false;
        String base = entryName.substring(abiPrefix.length());
        if (base.indexOf('/') >= 0) return false;
        if (!base.startsWith("lib") || !base.endsWith(".so")) return false;
        String body = base.substring(3, base.length() - 3);
        if (body.length() != ALIAS_BODY_LENGTH) return false;
        for (int i = 0; i < body.length(); i++) {
            char c = body.charAt(i);
            if (c < 'a' || c > 'z') return false;
        }
        return true;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format(Locale.ROOT, "%02x", b & 0xFF));
        }
        return sb.toString();
    }
}
