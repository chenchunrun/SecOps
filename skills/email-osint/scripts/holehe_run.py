#!/usr/bin/env python3
"""
holehe 本地运行脚本
自动使用 skill 内置的 holehe 源码
"""

import sys
import os
from pathlib import Path

# 添加本地 holehe 到 Python 路径
SCRIPT_DIR = Path(__file__).parent
SKILL_DIR = SCRIPT_DIR.parent
TOOLS_DIR = SKILL_DIR / "tools"

# 优先使用本地 holehe
sys.path.insert(0, str(TOOLS_DIR))

def main():
    if len(sys.argv) < 2:
        print("用法: python3 holehe_run.py <email>")
        print("示例: python3 holehe_run.py target@example.com")
        sys.exit(1)

    try:
        # 直接调用 holehe 的 main 函数（它会解析 sys.argv）
        from holehe.core import main as holehe_main
        holehe_main()

    except ImportError as e:
        print(f"错误: 缺少依赖 - {e}")
        print("请运行: pip3 install -r requirements.txt")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n用户中断")
        sys.exit(130)
    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
