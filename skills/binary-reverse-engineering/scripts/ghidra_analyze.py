#!/usr/bin/env python3
"""
Ghidra 无头模式分析脚本（跨平台）
用法:
    python3 ghidra_analyze.py <binary>
    python3 ghidra_analyze.py <binary> --decompile main
    python3 ghidra_analyze.py <binary> --export-all
    python3 ghidra_analyze.py <binary> --functions
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional, List


def find_ghidra_home() -> Optional[Path]:
    """查找 Ghidra 安装目录（跨平台）"""
    system = platform.system()

    # 环境变量优先
    if os.environ.get("GHIDRA_HOME"):
        ghidra_home = Path(os.environ["GHIDRA_HOME"])
        if ghidra_home.exists():
            return ghidra_home

    candidates = []

    if system == "Darwin":  # macOS
        # Homebrew 安装
        homebrew_paths = [
            Path("/opt/homebrew/Cellar/ghidra"),
            Path("/usr/local/Cellar/ghidra"),
        ]
        for base in homebrew_paths:
            if base.exists():
                versions = sorted(base.iterdir(), reverse=True)
                if versions:
                    candidates.append(versions[0] / "libexec")

        # 手动安装
        candidates.extend([
            Path("/Applications/ghidra"),
            Path.home() / "ghidra",
        ])

    elif system == "Windows":
        # 常见 Windows 安装路径
        candidates.extend([
            Path("C:/ghidra"),
            Path("C:/Program Files/ghidra"),
            Path("C:/Program Files (x86)/ghidra"),
            Path.home() / "ghidra",
        ])
        # 搜索版本目录
        for base in [Path("C:/"), Path("C:/Program Files")]:
            if base.exists():
                for d in base.iterdir():
                    if d.is_dir() and d.name.lower().startswith("ghidra"):
                        candidates.append(d)

    else:  # Linux
        candidates.extend([
            Path("/opt/ghidra"),
            Path("/usr/share/ghidra"),
            Path("/usr/local/ghidra"),
            Path.home() / "ghidra",
        ])
        # 搜索 /opt 下的版本目录
        opt = Path("/opt")
        if opt.exists():
            for d in opt.iterdir():
                if d.is_dir() and d.name.lower().startswith("ghidra"):
                    candidates.append(d)

    # 验证候选路径
    for path in candidates:
        if path.exists():
            analyze_headless = find_analyze_headless(path)
            if analyze_headless:
                return path

    return None


def find_analyze_headless(ghidra_home: Path) -> Optional[Path]:
    """查找 analyzeHeadless 可执行文件"""
    system = platform.system()

    if system == "Windows":
        candidates = [
            ghidra_home / "support" / "analyzeHeadless.bat",
            ghidra_home / "analyzeHeadless.bat",
        ]
    else:
        candidates = [
            ghidra_home / "support" / "analyzeHeadless",
            ghidra_home / "analyzeHeadless",
        ]

    for path in candidates:
        if path.exists():
            return path

    return None


def find_java_home() -> Optional[str]:
    """查找 Java 安装目录"""
    system = platform.system()

    # 环境变量优先
    if os.environ.get("JAVA_HOME"):
        return os.environ["JAVA_HOME"]

    if system == "Darwin":  # macOS
        # Homebrew OpenJDK
        candidates = [
            "/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home",
            "/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home",
            "/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home",
            "/usr/local/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home",
            "/usr/local/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home",
        ]
        # macOS 系统 Java
        result = subprocess.run(
            ["/usr/libexec/java_home"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            candidates.insert(0, result.stdout.strip())

        for path in candidates:
            if Path(path).exists():
                return path

    elif system == "Windows":
        # 常见 Windows Java 路径
        for base in [Path("C:/Program Files/Java"), Path("C:/Program Files/Eclipse Adoptium")]:
            if base.exists():
                for d in sorted(base.iterdir(), reverse=True):
                    if d.is_dir() and ("jdk" in d.name.lower() or "jre" in d.name.lower()):
                        return str(d)

    else:  # Linux
        candidates = [
            "/usr/lib/jvm/java-21-openjdk-amd64",
            "/usr/lib/jvm/java-17-openjdk-amd64",
            "/usr/lib/jvm/default-java",
        ]
        for path in candidates:
            if Path(path).exists():
                return path

    return None


def run_ghidra_headless(
    binary_path: Path,
    ghidra_home: Path,
    script: Optional[str] = None,
    script_args: Optional[List[str]] = None,
    timeout: int = 300
) -> subprocess.CompletedProcess:
    """运行 Ghidra 无头模式"""

    analyze_headless = find_analyze_headless(ghidra_home)
    if not analyze_headless:
        raise FileNotFoundError(f"analyzeHeadless not found in {ghidra_home}")

    # 设置 Java 环境
    env = os.environ.copy()
    java_home = find_java_home()
    if java_home:
        env["JAVA_HOME"] = java_home
        # 确保 Java 在 PATH 中
        java_bin = str(Path(java_home) / "bin")
        env["PATH"] = java_bin + os.pathsep + env.get("PATH", "")

    # 创建临时项目目录
    with tempfile.TemporaryDirectory(prefix="ghidra_") as tmp_dir:
        tmp_path = Path(tmp_dir)

        cmd = [
            str(analyze_headless),
            str(tmp_path),
            "TempProject",
            "-import", str(binary_path),
            "-deleteProject",
        ]

        if script:
            cmd.extend(["-postScript", script])
            if script_args:
                cmd.extend(script_args)

        # Windows 需要特殊处理
        if platform.system() == "Windows":
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=True,
                env=env
            )
        else:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env
            )

        return result


def get_functions(binary_path: Path, ghidra_home: Path) -> List[str]:
    """获取函数列表"""
    # 使用内置脚本或简单分析
    result = run_ghidra_headless(binary_path, ghidra_home)

    functions = []
    for line in result.stdout.split("\n"):
        # 解析 Ghidra 输出中的函数信息
        if "Function:" in line or "INFO  " in line and "(" in line:
            functions.append(line.strip())

    return functions


def decompile_function(binary_path: Path, ghidra_home: Path, func_name: str) -> str:
    """反编译指定函数"""
    # 创建临时脚本
    script_content = f'''
// Ghidra script to decompile function
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class DecompileFunc extends ghidra.app.script.GhidraScript {{
    @Override
    public void run() throws Exception {{
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        FunctionManager fm = currentProgram.getFunctionManager();
        for (Function func : fm.getFunctions(true)) {{
            if (func.getName().equals("{func_name}") ||
                func.getName().contains("{func_name}")) {{
                DecompileResults results = decomp.decompileFunction(func, 60, monitor);
                if (results.decompileCompleted()) {{
                    println("// Decompiled: " + func.getName());
                    println(results.getDecompiledFunction().getC());
                }}
                break;
            }}
        }}
        decomp.dispose();
    }}
}}
'''

    with tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False) as f:
        f.write(script_content)
        script_path = f.name

    try:
        result = run_ghidra_headless(
            binary_path,
            ghidra_home,
            script=script_path
        )
        return result.stdout
    finally:
        os.unlink(script_path)


def export_all(binary_path: Path, ghidra_home: Path, output_dir: Path) -> None:
    """导出所有反编译结果"""
    output_dir.mkdir(parents=True, exist_ok=True)

    # 简单分析并输出
    result = run_ghidra_headless(binary_path, ghidra_home)

    # 保存分析日志
    log_file = output_dir / f"{binary_path.stem}_analysis.log"
    log_file.write_text(result.stdout + "\n" + result.stderr)

    print(f"Analysis log saved to: {log_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Ghidra 无头模式分析（跨平台）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s sample.exe                    # 基础分析
  %(prog)s sample.exe --functions        # 列出函数
  %(prog)s sample.exe --decompile main   # 反编译 main
  %(prog)s sample.exe --export-all       # 导出全部

环境变量:
  GHIDRA_HOME    Ghidra 安装目录
"""
    )

    parser.add_argument("binary", help="二进制文件路径")
    parser.add_argument("--functions", "-f", action="store_true",
                        help="列出所有函数")
    parser.add_argument("--decompile", "-d", metavar="FUNC",
                        help="反编译指定函数")
    parser.add_argument("--export-all", "-e", action="store_true",
                        help="导出所有分析结果")
    parser.add_argument("--output", "-o", default="./ghidra_output",
                        help="输出目录 (默认: ./ghidra_output)")
    parser.add_argument("--ghidra-home", metavar="PATH",
                        help="Ghidra 安装目录")
    parser.add_argument("--timeout", type=int, default=300,
                        help="超时时间秒 (默认: 300)")

    args = parser.parse_args()

    binary_path = Path(args.binary)
    if not binary_path.exists():
        print(f"错误: 文件不存在: {binary_path}", file=sys.stderr)
        sys.exit(1)

    # 查找 Ghidra
    if args.ghidra_home:
        ghidra_home = Path(args.ghidra_home)
    else:
        ghidra_home = find_ghidra_home()

    if not ghidra_home:
        print("错误: 未找到 Ghidra 安装", file=sys.stderr)
        print("\n请设置 GHIDRA_HOME 环境变量或使用 --ghidra-home 参数", file=sys.stderr)
        print("\n安装方法:", file=sys.stderr)
        print("  macOS:   brew install ghidra", file=sys.stderr)
        print("  Windows: 下载 https://ghidra-sre.org/", file=sys.stderr)
        print("  Linux:   下载 https://ghidra-sre.org/", file=sys.stderr)
        sys.exit(1)

    print(f"Ghidra Home: {ghidra_home}")
    print(f"Binary: {binary_path}")
    print("-" * 50)

    try:
        if args.functions:
            functions = get_functions(binary_path, ghidra_home)
            print("\n[函数列表]")
            for func in functions[:50]:
                print(f"  {func}")
            if len(functions) > 50:
                print(f"  ... 共 {len(functions)} 个函数")

        elif args.decompile:
            print(f"\n[反编译: {args.decompile}]")
            output = decompile_function(binary_path, ghidra_home, args.decompile)
            print(output)

        elif args.export_all:
            output_dir = Path(args.output)
            print(f"\n[导出到: {output_dir}]")
            export_all(binary_path, ghidra_home, output_dir)

        else:
            # 默认：基础分析
            print("\n[基础分析]")
            result = run_ghidra_headless(binary_path, ghidra_home)

            # 提取关键信息
            lines = result.stdout.split("\n")
            for line in lines:
                if any(kw in line for kw in ["INFO", "Function", "Import", "Export", "Entry"]):
                    print(line)

            if result.returncode != 0:
                print(f"\n[警告] 分析可能不完整，返回码: {result.returncode}")
                if result.stderr:
                    print(result.stderr[:500])

    except subprocess.TimeoutExpired:
        print(f"错误: 分析超时 ({args.timeout}秒)", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
