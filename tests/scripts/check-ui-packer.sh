#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
javac --release 17 -cp tools/xop-pvm2-packer.jar -d "$stage" tests/java/com/yqsh/protector/packer/UiProtectionCheck.java
java -ea -cp "$stage:tools/xop-pvm2-packer.jar" com.yqsh.protector.packer.UiProtectionCheck
