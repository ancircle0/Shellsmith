# 运行时界面保护

这组可选能力用于提高运行中观察与调试的成本，默认关闭。GUI 的 APK「修改设置」及 AAB 设置中提供相同的运行时策略，CLI/TOML 调用核心的同一实现。

## 开关与使用

```bash
shield protect --input input.apk --output protected.apk \
  --secure-screen --adb-policy report --runtime-recheck \
  --screen-exempt-activities com.example.ShareActivity \
  --obfuscate-resource-names --resource-name-keep share_button
```

开发源码时应显式指定本次构建的 `--resources shield-stub/build/outputs/resources/resources.zip`，避免自动发现本机已安装的旧资源包。窗口/资源改写需要 Java 17 与新版内置 Packer，可用 `--ui-packer` 指定。无需同时启用 PVM2。

CLI 配置示例（`shield-cli.toml`）：

```toml
schema_version = 1
[protect]
input = "input.apk"
output = "protected.apk"

[protect.runtime_ui]
secure_screen = true
screen_exempt_activities = ["com.example.ShareActivity"]
adb_policy = "report"
runtime_recheck = true
obfuscate_resource_names = true
resource_name_keep = ["share_button"]
```

`--secure-screen=false` 等显式布尔值覆盖配置；关闭功能会清除配置中对应的例外名单。名单必须使用完整 Activity 类名或单个资源条目名，不支持通配符。

## 实际覆盖

- **防截图**：在 Activity 创建、启动和恢复阶段设置 `FLAG_SECURE`。改写已确认类型的 `Dialog.show()`、平台 `AlertDialog.Builder.show()` 和 `Window.clearFlags/setFlags/setAttributes` 调用。跨 DEX 解析应用子类；保留 `invoke-super`，保留 Builder/窗口的虚分派。Builder 返回后设置标记，未接管系统 Builder 实现。
- **窗口例外**：按窗口 Context 中 Activity 的完整类名匹配。找不到所属 Activity 的窗口默认保护；例外仅停止额外施加标记，不移除业务自身的安全标记。
- **ADB**：`off` 不读取；`report` 记录状态、不因此拒绝运行；`block` 对开启或未知状态拒绝运行。启动检查在业务 DEX 加载之前，进入前台立即检查，前台每 5 秒复查，并监听设置变化。拒绝后结束当前业务进程。
- **环境复查**：复用现有 Native 反调试/Root 策略，只在前台周期执行，不反复计算大文件完整性。`compatible` 仍不因 Root 单独拒绝，`strict` 保持原行为。`gmain/gdbus` 通用线程名改为辅助信号。
- **资源名称**：只改资源表中 `id` 独占的 key，保持数值 ID、类型和值。保留实际 DEX 字符串常量、指定名称、共享 key 和共享偏移；清除字符串池排序标记。UTF-8/UTF-16 均校验边界。稀疏/压缩条目、动态包、overlay 和未知块暂不处理。

资源名称第一版有意保守：原包包含 **任意 Native SO 或 assets 文件**，或者出现动态资源查名/代码加载特征时，整包跳过名称改写，并报告原因。不是只看开关就声称保护生效。AAB 暂不支持资源名称混淆，开启时明确拒绝；其余运行时功能覆盖 base 和已暂存的 feature DEX。Xop 独立壳不支持这组开关，也明确拒绝。

进度事件包含生效策略、窗口改写数量、未确认的同名调用数量、资源改名/保留/跳过数量与原因。CLI `--json` 和 GUI 共用这些事件；不向 APK 写入原名映射。旧 Runtime 未声明 `runtime_ui=true` 时，禁止开启运行时功能。

## 防护边界

`FLAG_SECURE` 不隐藏视图树、按钮文字、接口返回内容，也不阻止 `adb input`。没有把开启无障碍当作攻击，更没有禁用 TalkBack。USB 调试开关不是连接状态；API 30 起的无线调试读取 AOSP 隐藏设置，部分 ROM 无法读取时明确为未知，因此应先用 `report` 回归后再选 `block`。

反射/Native 调用、无法解析继承链的第三方 Builder、自建 WindowManager 窗口、系统修改和 Hook 绕过不属于完整覆盖。前台复查也不保证检测到改名或隐藏的注入。客户端保护不能阻止所有运行时观察，不能替代服务端鉴权、数据最小化与接口风控。

## 构建与验证

```bash
bash scripts/build-ui-packer.sh
bash tests/scripts/check-ui-packer.sh
make build-stub
cargo test -p shield-core -p shield-cli -p mocika-shield
cargo build --release -p shield-cli
ANDROID_HOME=/path/to/sdk RUN_DEVICE_TEST=1 ANDROID_SERIAL=设备序列号 \
  bash tests/scripts/run-runtime-ui-e2e.sh
```

Packer 构建复用仓库已有依赖 JAR，不下载新依赖；更新后需同步 `scripts/check-release-ready.sh` 中的摘要。端到端脚本使用独立包 `dev.mocika.shield.uiprobe` 和测试证书，验证 Activity、Dialog、平台 Builder、例外、资源数值 ID、名称保留、签名和 ADB 启动阻断；不修改设备 ADB 设置，不卸载同名包。产物和设备日志保存在 `target/runtime-ui-e2e`。

受保护截图在有些设备上返回黑图，在有些设备上直接失败；不能要求所有 ROM 返回同一种图像。脚本保留实际截图或 `secure-capture.txt`，需要结合窗口标记与例外截图核验。无线调试状态切换、运行期间阻断、旋转、多窗口、TalkBack、录屏、第三方 Dialog 和多种 ROM 仍应纳入业务真机回归。
