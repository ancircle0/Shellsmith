package dev.mocika.shield.loader;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Log;

import dev.mocika.shield.stub.BuildConfig;

import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 壳原生库的启动期完整性校验。
 *
 * 打包时按 ABI 记录壳库明文 SHA-256 并写入 manifest；此处读取设备上实际安装的
 * APK 内对应条目，重新计算摘要后比对。壳库在打包流程中只改文件名、不改字节，
 * 因此构建期摘要与运行期字节一致。
 *
 * <p>该检查只提高替换壳库的成本，不构成机密性保证：能改写 APK 的攻击者同样
 * 能改写 manifest 中的摘要值。默认关闭，见 {@link BuildConfig#NATIVE_SELF_CHECK}。
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
     * <p>开关关闭或字段缺失时直接返回，不做任何阻断。
     *
     * @throws SecurityException 摘要不一致（仅开关开启时抛出）
     */
    static void verify(Context context) throws Exception {
        if (!BuildConfig.NATIVE_SELF_CHECK) return;
        String expected = readExpectedDigest(context);
        if (expected == null) return;
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
     * 计算已安装 APK 内壳库的 SHA-256（小写十六进制）。
     *
     * <p>按 lib/&lt;abi&gt;/ 下的别名形状定位：仅壳库使用 16 位小写字母别名，
     * 业务库保留原名，因此不会误取。ABI 遍历顺序与 {@link #selectDeviceAbiDigest}
     * 一致，保证比对的期望值与实际字节来自同一个 ABI。
     */
    private static String readInstalledDigest(Context context) throws Exception {
        String[] abis = Build.SUPPORTED_ABIS;
        if (abis == null || abis.length == 0) return null;
        String apkPath = context.getApplicationInfo().sourceDir;
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
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        java.util.Enumeration<? extends ZipEntry> entries = zip.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            if (!isShellLibraryEntry(entry.getName(), prefix)) continue;
            try (InputStream is = zip.getInputStream(entry)) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = is.read(buffer)) != -1) {
                    digest.update(buffer, 0, read);
                }
            }
            return toHex(digest.digest());
        }
        return null;
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
