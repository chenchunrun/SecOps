#!/usr/bin/env python3
"""
blackbird 本地运行脚本
自动使用 skill 内置的 blackbird 源码
"""

import sys
import os
import subprocess
from pathlib import Path

# 默认超时时间（秒）
DEFAULT_TIMEOUT = 120  # blackbird 需要较长时间扫描多个平台

# 路径设置
SCRIPT_DIR = Path(__file__).parent
SKILL_DIR = SCRIPT_DIR.parent
BLACKBIRD_DIR = SKILL_DIR / "tools" / "blackbird"
BLACKBIRD_PY = BLACKBIRD_DIR / "blackbird.py"

def main():
    if not BLACKBIRD_PY.exists():
        print(f"错误: blackbird.py 未找到: {BLACKBIRD_PY}")
        sys.exit(1)

    # 传递所有参数给 blackbird.py
    args = sys.argv[1:]

    if not args:
        print("用法: python3 blackbird_run.py [options]")
        print("")
        print("示例:")
        print("  python3 blackbird_run.py -u <username>           # 搜索用户名")
        print("  python3 blackbird_run.py -u user1 user2          # 多用户名")
        print("  python3 blackbird_run.py -e <email>              # 搜索邮箱")
        print("  python3 blackbird_run.py -u <username> --json    # JSON输出")
        print("  python3 blackbird_run.py -u <username> --no-update  # 跳过更新检查")
        print("")
        # 显示完整帮助
        args = ["--help"]

    # 切换到 blackbird 目录执行（某些功能需要相对路径）
    cmd = [sys.executable, str(BLACKBIRD_PY)] + args

    try:
        result = subprocess.run(
            cmd,
            cwd=str(BLACKBIRD_DIR),
            timeout=DEFAULT_TIMEOUT,
            # 不捕获输出，直接显示
        )
        sys.exit(result.returncode)
    except subprocess.TimeoutExpired:
        print(f"\n错误: 执行超时（>{DEFAULT_TIMEOUT}秒）")
        sys.exit(124)
    except KeyboardInterrupt:
        print("\n用户中断")
        sys.exit(130)
    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
