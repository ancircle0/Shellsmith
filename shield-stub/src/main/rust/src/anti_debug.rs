/// 反调试检测：通过 /proc 文件系统检测 ptrace 调试器与 Frida 注入。
/// 所有检测均基于标准库文件读取，无额外 Cargo 依赖。
use std::fs;
use std::io::{BufRead, BufReader};

/// Frida 注入到目标进程后必然出现在内存映射中的库名特征。
const FRIDA_MAP_SIGS: &[&str] = &[
    "frida-agent",
    "frida-gadget",
    "libfrida",
    "gum-js-loop", // Frida Gum JS 引擎线程段
];

/// Frida 依赖的 GLib 内部线程名特征。
/// phantom-frida 等工具重命名了 .so 文件名，但无法重命名 GLib 线程，此处作为补充检测。
const FRIDA_THREAD_SIGS: &[&str] = &[
    "gmain",      // GLib 主循环线程
    "gdbus",      // D-Bus 通信线程（Frida 进程间通信依赖）
    "pool-frida", // Frida 线程池
    "gum-js-loop",
];

/// Frida server 默认监听端口的十六进制大写形式（/proc/net/tcp 中端口以十六进制表示）。
const FRIDA_PORTS: &[&str] = &[
    ":69AA", // 27042
    ":69AB", // 27043
];

/// Frida server 在设备上的常见落地路径。
const FRIDA_FILE_SIGS: &[&str] = &[
    "/data/local/tmp/frida-server",
    "/data/local/tmp/re.frida.server",
    "/data/local/tmp/frida",
];

/// Hook 框架注入后在进程地址空间留下的映射名特征。
/// 仅匹配通用行为特征，不针对特定工具的版本。
const HOOK_MAP_SIGS: &[&str] = &["xposed", "lsposed", "edxposed", "substrate"];

/// 综合反调试检测入口。任一检测命中即返回 true。
/// 检测顺序：TracerPid（最快，单次读取）→ maps 扫描 → 线程名扫描（兜底）。
pub fn check() -> bool {
    check_tracer_pid()
        || check_frida_maps()
        || check_frida_threads()
        || check_frida_ports()
        || check_frida_files()
        || check_hook_frameworks()
}

/// 检测 ptrace 类调试器（Android Studio / IDA / lldb 等）。
/// 读取 /proc/self/status 中的 TracerPid 字段：非零表示已有进程通过 ptrace 附加。
fn check_tracer_pid() -> bool {
    let file = match fs::File::open("/proc/self/status") {
        Ok(f) => f,
        Err(_) => return false,
    };
    for line in BufReader::new(file).lines() {
        let Ok(line) = line else { continue };
        if line.starts_with("TracerPid") {
            return line
                .split(':')
                .nth(1)
                .and_then(|s| s.trim().parse::<u32>().ok())
                .map(|pid| pid != 0)
                .unwrap_or(false);
        }
    }
    false
}

/// 检测 Frida 注入：扫描 /proc/self/maps 中的 Frida 库特征字符串。
/// Frida 注入后必然将 frida-agent.so / frida-gadget.so 加载进进程地址空间，
/// 这些映射条目无法对自身进程隐藏。
fn check_frida_maps() -> bool {
    let file = match fs::File::open("/proc/self/maps") {
        Ok(f) => f,
        Err(_) => return false,
    };
    for line in BufReader::new(file).lines() {
        let Ok(line) = line else { continue };
        for sig in FRIDA_MAP_SIGS {
            if line.contains(sig) {
                return true;
            }
        }
    }
    false
}

/// 辅助检测：遍历 /proc/self/task/*/comm，匹配 Frida 依赖的 GLib 线程名。
/// 作为 maps 扫描的兜底：覆盖重命名了库文件但无法重命名内部 GLib 线程的变种注入工具。
fn check_frida_threads() -> bool {
    let task_dir = match fs::read_dir("/proc/self/task") {
        Ok(d) => d,
        Err(_) => return false,
    };
    for entry in task_dir.flatten() {
        let comm_path = entry.path().join("comm");
        let Ok(comm) = fs::read_to_string(&comm_path) else {
            continue;
        };
        let comm = comm.trim();
        for sig in FRIDA_THREAD_SIGS {
            if comm.contains(sig) {
                return true;
            }
        }
    }
    false
}

/// 判断 /proc/net/tcp 的一行是否指向 Frida 默认监听端口。
fn line_has_frida_port(line: &str) -> bool {
    // 局部地址字段形如 "00000000:69AA"，端口以十六进制大写表示
    match line.split_whitespace().nth(1) {
        Some(local) => FRIDA_PORTS.iter().any(|sig| local.ends_with(sig)),
        None => false,
    }
}

/// 检测 Frida server 正在监听的默认端口。
/// 扫描 /proc/net/tcp 与 tcp6；部分 ROM 限制该文件读取，读取失败按未命中处理。
fn check_frida_ports() -> bool {
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let file = match fs::File::open(path) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            .any(|line| line_has_frida_port(&line))
        {
            return true;
        }
    }
    false
}

/// 检测设备上已落地的 Frida server 文件。
/// 纯路径存在性检查，不做文件内容读取，成本极低。
fn check_frida_files() -> bool {
    FRIDA_FILE_SIGS
        .iter()
        .any(|path| std::path::Path::new(path).exists())
}

/// 检测 Hook 框架：扫描 /proc/self/maps 中的注入映射名。
/// 与 Frida 的 maps 扫描分开，便于诊断时区分命中来源。
fn check_hook_frameworks() -> bool {
    let file = match fs::File::open("/proc/self/maps") {
        Ok(f) => f,
        Err(_) => return false,
    };
    for line in BufReader::new(file).lines() {
        let Ok(line) = line else { continue };
        let lower = line.to_lowercase();
        for sig in HOOK_MAP_SIGS {
            if lower.contains(sig) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 识别_frida_默认监听端口() {
        // /proc/net/tcp 行格式：sl local_address rem_address st ...
        assert!(line_has_frida_port(
            "  0: 00000000:69AA 00000000:0000 0A 00000000:00000000 00:00000000 00000000"
        ));
        assert!(line_has_frida_port(
            "  1: 00000000000000000000000000000000:69AB 00000000000000000000000000000000:0000 0A"
        ));
    }

    #[test]
    fn 不误判其他端口与残缺行() {
        // 27042 之外的端口不应命中
        assert!(!line_has_frida_port(
            "  0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000"
        ));
        // 只以端口结尾才命中，避免 0:69AA 之类的中间字段误判
        assert!(!line_has_frida_port("  0: 69AA0000:1234 00000000:0000 0A"));
        // 空行与表头
        assert!(!line_has_frida_port(""));
        assert!(!line_has_frida_port("  sl  local_address rem_address"));
    }
}
