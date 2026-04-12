#!/bin/bash
# macOS 入侵检查统一入口 v1.0
# 用法: ./ir.sh [模式]
#   (无参数)    - 摘要报告 (推荐首选)
#   quick       - 快速扫描
#   full        - 完整检查 (所有模块)
#   persistence - 持久化检查
#   network     - 网络分析
#   signature   - 签名检查
#   forensic    - 取证工件

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODE="${1:-summary}"

# 颜色
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'

run_script() {
    local script="$1"
    local name="$2"
    if [[ -x "$SCRIPT_DIR/$script" ]]; then
        echo ""
        echo -e "${BLUE}━━━ $name ━━━${NC}"
        bash "$SCRIPT_DIR/$script"
    else
        echo "脚本不存在: $script"
    fi
}

case "$MODE" in
    summary|s|"")
        run_script "summary_scan.sh" "摘要报告"
        ;;
    quick|q)
        run_script "quick_scan.sh" "快速扫描"
        ;;
    full|f|all)
        run_script "summary_scan.sh" "摘要报告"
        run_script "quick_scan.sh --full" "快速扫描(完整)"
        run_script "deep_persistence.sh" "深度持久化检查"
        run_script "network_analysis.sh" "网络分析"
        run_script "codesign_check.sh" "签名检查"
        ;;
    persistence|p)
        run_script "deep_persistence.sh" "持久化检查"
        ;;
    network|n)
        run_script "network_analysis.sh" "网络分析"
        ;;
    signature|sig)
        run_script "codesign_check.sh" "签名检查"
        ;;
    forensic|for)
        run_script "forensic_artifacts.sh" "取证工件"
        ;;
    help|h|-h|--help)
        echo "macOS 入侵检查工具"
        echo ""
        echo "用法: ./ir.sh [模式]"
        echo ""
        echo "模式:"
        echo "  (空)/summary  摘要报告 - 10项关键检查，5秒完成 [推荐]"
        echo "  quick         快速扫描 - 详细输出，30秒"
        echo "  full          完整检查 - 所有模块，2-3分钟"
        echo "  persistence   持久化检查"
        echo "  network       网络分析"
        echo "  signature     签名检查"
        echo "  forensic      取证工件"
        echo ""
        echo "示例:"
        echo "  ./ir.sh           # 快速查看系统安全状态"
        echo "  ./ir.sh full      # 发现问题后深入检查"
        ;;
    *)
        echo "未知模式: $MODE"
        echo "运行 ./ir.sh help 查看帮助"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}完成${NC}"
