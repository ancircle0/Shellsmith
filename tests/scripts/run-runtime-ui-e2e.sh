#!/usr/bin/env bash
# 独立测试包，不修改设备 ADB 设置；产物留在 target 供截图与人工回归。
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT="$PWD"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
test -n "$SDK" || { echo '请设置 ANDROID_HOME'; exit 1; }
BUILD_TOOLS="${UI_BUILD_TOOLS:-$SDK/build-tools/35.0.0}"
ANDROID_JAR="$SDK/platforms/android-35/android.jar"
WORK="${UI_E2E_OUTPUT:-$ROOT/target/runtime-ui-e2e}"
FIXTURE="$ROOT/tests/fixtures/runtime-ui"
mkdir -p "$WORK/classes" "$WORK/gen" "$WORK/dex"
bash tests/scripts/check-ui-packer.sh
"$BUILD_TOOLS/aapt2" compile --dir "$FIXTURE/res" -o "$WORK/resources.zip"
"$BUILD_TOOLS/aapt2" link -o "$WORK/input-unsigned.apk" --manifest "$FIXTURE/AndroidManifest.xml" -I "$ANDROID_JAR" --java "$WORK/gen" "$WORK/resources.zip"
javac --release 8 -cp "$ANDROID_JAR" -d "$WORK/classes" "$FIXTURE/UiProbe.java" "$WORK/gen/dev/mocika/shield/uiprobe/R.java"
jar cf "$WORK/classes.jar" -C "$WORK/classes" .
"$BUILD_TOOLS/d8" --lib "$ANDROID_JAR" --min-api 23 --output "$WORK/dex" "$WORK/classes.jar"
(cd "$WORK/dex" && zip -q "$WORK/input-unsigned.apk" classes.dex)
if [[ ! -f "$WORK/test.p12" ]]; then
  keytool -genkeypair -noprompt -keystore "$WORK/test.p12" -storetype PKCS12 -storepass shellsmith-test -keypass shellsmith-test -alias probe -keyalg RSA -validity 365 -dname 'CN=Shellsmith UI Test'
fi
sign() { java -jar tools/apksigner.jar sign --ks "$WORK/test.p12" --ks-pass pass:shellsmith-test --ks-key-alias probe --out "$2" "$1"; }
sign "$WORK/input-unsigned.apk" "$WORK/input.apk"
target/release/shield protect --resources "$ROOT/shield-stub/build/outputs/resources/resources.zip" --input "$WORK/input.apk" --output "$WORK/protected.apk" \
  --secure-screen --screen-exempt-activities 'dev.mocika.shield.uiprobe.UiProbe$ShareActivity' \
  --adb-policy report --runtime-recheck --obfuscate-resource-names --resource-name-keep kept_action \
  --ui-packer "$ROOT/tools/xop-pvm2-packer.jar" --json > "$WORK/protect.jsonl"
sign "$WORK/protected.apk" "$WORK/protected-signed.apk"
java -jar tools/apksigner.jar verify --verbose "$WORK/protected-signed.apk" > "$WORK/signature.txt"
"$BUILD_TOOLS/aapt2" dump resources "$WORK/input.apk" > "$WORK/resources-before.txt"
"$BUILD_TOOLS/aapt2" dump resources "$WORK/protected-signed.apk" > "$WORK/resources-after.txt"
python3 - "$WORK" <<'PY'
import pathlib,re,sys
p=pathlib.Path(sys.argv[1])
def entries(file):
    return dict(re.findall(r'resource (0x[0-9a-f]+) id/(\w+)', (p/file).read_text()))
before,after=entries('resources-before.txt'),entries('resources-after.txt')
assert before and before.keys()==after.keys(), (before,after)
for id,name in before.items():
    assert (after[id]!=name) if name=='private_action' else (after[id]==name), (name,after[id])
report=(p/'protect.jsonl').read_text()
assert '窗口保护' in report and '资源名称保护' in report
PY
target/release/shield protect --resources "$ROOT/shield-stub/build/outputs/resources/resources.zip" --input "$WORK/input.apk" --output "$WORK/blocked.apk" --adb-policy block --json > "$WORK/block.jsonl"
sign "$WORK/blocked.apk" "$WORK/blocked-signed.apk"
if [[ "${RUN_DEVICE_TEST:-0}" == 1 ]]; then
  ADB=(adb)
  [[ -z "${ANDROID_SERIAL:-}" ]] || ADB+=(-s "$ANDROID_SERIAL")
  PACKAGE=dev.mocika.shield.uiprobe
  # 不卸载同名包；若签名不同让安装失败，避免清除已有数据。
  "${ADB[@]}" install -r "$WORK/protected-signed.apk"
  launch() {
    local activity="$1" expected="$2" label="$3"
    "${ADB[@]}" shell am force-stop "$PACKAGE"
    "${ADB[@]}" shell am start -W -n "'$PACKAGE/$activity'" --ez expect_secure "$expected" --ez builder "${4:-false}"
    sleep 2
    local pid
    pid=$("${ADB[@]}" shell pidof "$PACKAGE" | tr -d '\r')
    test -n "$pid"
    "${ADB[@]}" logcat -d --pid="$pid" > "$WORK/$label.log"
    rg -q "UI_PROBE_OK secure=$expected" "$WORK/$label.log"
  }
  launch .UiProbe true secure
  "${ADB[@]}" exec-out screencap -p > "$WORK/secure.png"
  if ! file "$WORK/secure.png" | rg -q 'PNG image'; then mv "$WORK/secure.png" "$WORK/secure-capture.txt"; fi
  "${ADB[@]}" shell input keyevent KEYCODE_HOME
  "${ADB[@]}" shell am start -W -n "$PACKAGE/.UiProbe" --ez expect_secure true
  sleep 2
  launch .UiProbe true builder true
  launch '.UiProbe$ShareActivity' false exempt
  "${ADB[@]}" exec-out screencap -p > "$WORK/exempt.png"
  "${ADB[@]}" install -r "$WORK/blocked-signed.apk"
  # 当前 ADB 已开启；限制模式应在业务 Application/Activity 前拒绝加载。
  stamp=$("${ADB[@]}" shell "date '+%m-%d %H:%M:%S.000'" | tr -d '\r')
  "${ADB[@]}" shell am start -W -n "$PACKAGE/.UiProbe" || true
  sleep 2
  "${ADB[@]}" logcat -d -T "$stamp" -s AndroidRuntime:E RuntimeSecurity:I UiProbe:I '*:S' > "$WORK/blocked.log"
  rg -q 'SecurityException: U01' "$WORK/blocked.log"
  if "${ADB[@]}" shell pidof "$PACKAGE"; then echo '限制模式未停止业务进程'; exit 1; fi
  "${ADB[@]}" install -r "$WORK/protected-signed.apk"
  echo '真机 Activity/Dialog 安全标记、例外与 ADB 启动限制通过；截图保留供检查。'
fi
echo "界面保护端到端检查通过，产物：$WORK"
