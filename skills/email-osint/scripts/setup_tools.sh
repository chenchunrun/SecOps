#!/bin/bash
# email-osint 工具安装脚本
# 用法: bash scripts/setup_tools.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(dirname "$SCRIPT_DIR")"

echo "=================================================="
echo "email-osint 工具安装"
echo "=================================================="
echo ""

# 检查 Python 版本
python_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "Python 版本: $python_version"

# 安装依赖
echo ""
echo "安装 Python 依赖..."
pip3 install -r "$SKILL_DIR/requirements.txt" --quiet

# 验证安装
echo ""
echo "验证安装..."

# 验证 holehe 依赖
python3 -c "import httpx, trio, bs4, colorama, termcolor, tqdm" && echo "✅ holehe 依赖已安装" || echo "❌ holehe 依赖安装失败"

# 验证 blackbird 依赖
python3 -c "import aiohttp, requests, rich, PIL, reportlab" && echo "✅ blackbird 依赖已安装" || echo "❌ blackbird 依赖安装失败"

# 检查本地工具
echo ""
echo "检查本地工具..."
if [ -d "$SKILL_DIR/tools/holehe" ]; then
    echo "✅ holehe 源码: $SKILL_DIR/tools/holehe"
else
    echo "❌ holehe 源码未找到"
fi

if [ -f "$SKILL_DIR/tools/blackbird/blackbird.py" ]; then
    echo "✅ blackbird 源码: $SKILL_DIR/tools/blackbird"
else
    echo "❌ blackbird 源码未找到"
fi

echo ""
echo "=================================================="
echo "安装完成!"
echo ""
echo "使用方法:"
echo "  holehe:    python3 $SKILL_DIR/scripts/holehe_run.py <email>"
echo "  blackbird: python3 $SKILL_DIR/scripts/blackbird_run.py -u <username>"
echo "=================================================="
