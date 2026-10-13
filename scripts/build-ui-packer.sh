#!/usr/bin/env bash
# 复用随项目分发的依赖 JAR，只更新本次界面保护入口与实现。
set -euo pipefail
cd "$(dirname "$0")/.."
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
source_dir=third_party/xopprotector/packer/src/main/java/com/yqsh/protector/packer
javac --release 17 -cp tools/xop-pvm2-packer.jar -d "$stage/classes" \
  "$source_dir/PackerMain.java" "$source_dir/UiCallsiteRewriter.java" \
  "$source_dir/UiProtectionTool.java" "$source_dir/ResourceNameObfuscator.java"
cp tools/xop-pvm2-packer.jar "$stage/packer.jar"
jar --update --file "$stage/packer.jar" -C "$stage/classes" .
mv "$stage/packer.jar" tools/xop-pvm2-packer.jar
echo '界面保护 Packer 已更新；发布前同步 check-release-ready.sh 中的 SHA-256。'
