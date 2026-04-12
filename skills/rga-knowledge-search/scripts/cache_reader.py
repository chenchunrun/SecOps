#!/usr/bin/env python3
"""
RGA 缓存读取器 - 从 ripgrep-all 缓存中读取已提取的文档文本

支持滑动分片读取，防止超出 LLM 上下文窗口限制。

用法:
    python cache_reader.py <文件路径>                    # 读取（默认限制）
    python cache_reader.py <文件> --around "关键词"      # 从关键词位置读取上下文
    python cache_reader.py <文件> --page 2               # 翻页读取
    python cache_reader.py <文件> --offset 10000         # 从指定位置读取
"""

import argparse
import os
import platform
import re
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

# 默认分片大小 (约 12500 tokens)
DEFAULT_CHUNK_SIZE = 50000

# 单行最大长度
MAX_LINE_LENGTH = 500

# 制表符宽度
TAB_WIDTH = 4


def format_output(text: str, start_line: int = 1, show_line_numbers: bool = False,
                  truncate_long_lines: bool = True, expand_tabs: bool = True) -> str:
    """格式化输出文本

    Args:
        text: 原始文本
        start_line: 起始行号 (1-based)
        show_line_numbers: 是否显示行号 (cat -n 格式)
        truncate_long_lines: 是否截断超长行 (MAX_LINE_LENGTH)
        expand_tabs: 是否将制表符转换为空格

    Returns:
        格式化后的文本
    """
    lines = text.split('\n')
    result = []

    for i, line in enumerate(lines):
        line_num = start_line + i

        # 制表符转换
        if expand_tabs:
            line = line.replace('\t', ' ' * TAB_WIDTH)

        # 超长行截断
        if truncate_long_lines and len(line) > MAX_LINE_LENGTH:
            line = line[:MAX_LINE_LENGTH] + '...[截断]'

        # 行号格式化 (模拟 cat -n: 右对齐6位 + tab + 内容)
        if show_line_numbers:
            result.append(f"{line_num:>6}\t{line}")
        else:
            result.append(line)

    return '\n'.join(result)


def get_cache_path() -> Path:
    """获取 rga 缓存数据库路径"""
    system = platform.system()

    if system == "Linux":
        cache_dir = Path.home() / ".cache" / "ripgrep-all"
    elif system == "Darwin":  # macOS
        cache_dir = Path.home() / "Library" / "Caches" / "ripgrep-all"
    elif system == "Windows":
        cache_dir = Path(os.environ.get("LOCALAPPDATA", "")) / "ripgrep-all" / "cache"
    else:
        cache_dir = Path.home() / ".cache" / "ripgrep-all"

    return cache_dir / "cache.sqlite3"


def decompress_zstd(data: bytes) -> str:
    """解压 ZSTD 压缩的数据"""
    try:
        import zstandard as zstd
        decompressor = zstd.ZstdDecompressor()
        with decompressor.stream_reader(data) as reader:
            decompressed = reader.read()
        return decompressed.decode('utf-8', errors='replace')
    except ImportError:
        try:
            import zstd
            return zstd.decompress(data).decode('utf-8', errors='replace')
        except ImportError:
            print("错误: 需要安装 zstandard 库", file=sys.stderr)
            print("运行: pip install zstandard", file=sys.stderr)
            sys.exit(1)


def normalize_path(file_path: str) -> str:
    """标准化文件路径"""
    return str(Path(file_path).expanduser().resolve())


def read_cache(file_path: str, db_path: Path = None) -> str | None:
    """从缓存读取文件的完整文本"""
    if db_path is None:
        db_path = get_cache_path()

    if not db_path.exists():
        print(f"缓存数据库不存在: {db_path}", file=sys.stderr)
        print("提示: 先运行 rga 搜索以生成缓存", file=sys.stderr)
        return None

    normalized = normalize_path(file_path)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT text_content_zstd FROM preproc_cache WHERE file_path = ?",
        (normalized,)
    )
    row = cursor.fetchone()

    if row is None:
        cursor.execute(
            "SELECT file_path, text_content_zstd FROM preproc_cache WHERE file_path LIKE ?",
            (f"%{Path(file_path).name}",)
        )
        rows = cursor.fetchall()
        if rows:
            if len(rows) == 1:
                row = (rows[0][1],)
            else:
                print(f"找到多个匹配文件:", file=sys.stderr)
                for r in rows:
                    print(f"  {r[0]}", file=sys.stderr)
                conn.close()
                return None

    conn.close()

    if row is None:
        print(f"缓存中未找到: {file_path}", file=sys.stderr)
        print("提示: 先运行 rga 搜索该文件以生成缓存", file=sys.stderr)
        return None

    return decompress_zstd(row[0])


def slice_by_offset(text: str, offset: int, length: int) -> tuple[str, dict]:
    """从指定偏移量开始切片"""
    total = len(text)
    start = max(0, offset)
    end = min(total, start + length)

    # 调整到行边界
    if start > 0:
        line_start = text.rfind('\n', 0, start)
        if line_start != -1:
            start = line_start + 1

    if end < total:
        line_end = text.find('\n', end)
        if line_end != -1:
            end = line_end

    content = text[start:end]

    meta = {
        "start": start,
        "end": end,
        "total_chars": total,
        "has_more": end < total,
        "has_prev": start > 0
    }

    return content, meta


def slice_by_page(text: str, page: int, page_size: int) -> tuple[str, dict]:
    """翻页式切片"""
    total_chars = len(text)
    total_pages = max(1, (total_chars + page_size - 1) // page_size)

    # 范围检查
    if page < 1:
        return "", {"error": f"页码必须大于 0"}
    if page > total_pages:
        return "", {"error": f"页码 {page} 超出范围 (共 {total_pages} 页)"}

    offset = (page - 1) * page_size
    content, meta = slice_by_offset(text, offset, page_size)

    meta["page"] = page
    meta["total_pages"] = total_pages

    return content, meta


def slice_around_keyword(text: str, keyword: str, context_size: int,
                         occurrence: int = 1, ignore_case: bool = True) -> tuple[str, dict]:
    """从关键词位置开始切片，包含上下文"""
    flags = re.IGNORECASE if ignore_case else 0
    matches = list(re.finditer(re.escape(keyword), text, flags))

    if not matches:
        return "", {"error": f"未找到关键词: {keyword}", "found": 0}

    if occurrence > len(matches):
        occurrence = len(matches)

    match = matches[occurrence - 1]
    center = match.start()

    # 计算上下文范围
    half_context = context_size // 2
    start = max(0, center - half_context)
    end = min(len(text), center + half_context)

    # 调整到行边界
    if start > 0:
        line_start = text.rfind('\n', 0, start)
        if line_start != -1:
            start = line_start + 1

    if end < len(text):
        line_end = text.find('\n', end)
        if line_end != -1:
            end = line_end

    content = text[start:end]

    # 标记关键词位置（相对于切片）
    keyword_pos = center - start

    meta = {
        "keyword": keyword,
        "occurrence": occurrence,
        "total_matches": len(matches),
        "keyword_pos": keyword_pos,
        "start": start,
        "end": end,
        "total_chars": len(text),
        "has_more": end < len(text),
        "has_prev": start > 0
    }

    return content, meta


def slice_by_lines(text: str, start_line: int, num_lines: int) -> tuple[str, dict]:
    """按行切片"""
    lines = text.split('\n')
    total_lines = len(lines)

    # 范围检查
    if start_line > total_lines:
        return "", {"error": f"起始行 {start_line} 超出范围 (共 {total_lines} 行)"}

    start_idx = max(0, start_line - 1)  # 1-based to 0-based
    end_idx = min(total_lines, start_idx + num_lines)

    content = '\n'.join(lines[start_idx:end_idx])

    meta = {
        "start_line": start_idx + 1,
        "end_line": end_idx,
        "total_lines": total_lines,
        "has_more": end_idx < total_lines,
        "has_prev": start_idx > 0
    }

    return content, meta


def get_indent_level(line: str) -> int:
    """获取行的缩进级别 (空格数)"""
    stripped = line.lstrip()
    if not stripped:  # 空行
        return -1
    return len(line) - len(stripped)


def slice_by_indent(text: str, start_line: int, base_indent: int = None,
                    max_lines: int = 200) -> tuple[str, dict]:
    """基于缩进级别智能提取代码块

    从指定行开始，提取同级或更深缩进的连续内容，直到遇到更浅缩进。
    适用于提取完整的函数、类定义、配置块等结构化内容。

    Args:
        text: 原始文本
        start_line: 起始行号 (1-based)
        base_indent: 基准缩进级别，None 则自动检测起始行的缩进
        max_lines: 最大提取行数

    Returns:
        (content, meta) 元组
    """
    lines = text.split('\n')
    total_lines = len(lines)

    start_idx = max(0, start_line - 1)
    if start_idx >= total_lines:
        return "", {"error": f"起始行 {start_line} 超出范围 (共 {total_lines} 行)"}

    # 自动检测基准缩进
    if base_indent is None:
        base_indent = get_indent_level(lines[start_idx])
        if base_indent < 0:  # 起始行是空行，向下找第一个非空行
            for i in range(start_idx, min(start_idx + 10, total_lines)):
                indent = get_indent_level(lines[i])
                if indent >= 0:
                    base_indent = indent
                    start_idx = i
                    break
            if base_indent < 0:
                base_indent = 0

    result_lines = []
    end_idx = start_idx
    in_block = True

    for i in range(start_idx, min(start_idx + max_lines, total_lines)):
        line = lines[i]
        indent = get_indent_level(line)

        # 空行保留在块内
        if indent < 0:
            result_lines.append(line)
            end_idx = i + 1
            continue

        # 缩进更浅，块结束
        if in_block and indent < base_indent and i > start_idx:
            break

        result_lines.append(line)
        end_idx = i + 1

    content = '\n'.join(result_lines)

    meta = {
        "mode": "indent",
        "start_line": start_idx + 1,
        "end_line": end_idx,
        "total_lines": total_lines,
        "base_indent": base_indent,
        "extracted_lines": len(result_lines),
        "has_more": end_idx < total_lines,
        "has_prev": start_idx > 0
    }

    return content, meta


def list_cached_files(pattern: str = None, db_path: Path = None) -> list:
    """列出缓存中的文件"""
    if db_path is None:
        db_path = get_cache_path()

    if not db_path.exists():
        print(f"缓存数据库不存在: {db_path}", file=sys.stderr)
        return []

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    if pattern:
        cursor.execute(
            "SELECT DISTINCT file_path, adapter FROM preproc_cache WHERE file_path LIKE ? ORDER BY file_path",
            (f"%{pattern}%",)
        )
    else:
        cursor.execute("SELECT DISTINCT file_path, adapter FROM preproc_cache ORDER BY file_path")

    rows = cursor.fetchall()
    conn.close()

    return rows


def get_cache_info(file_path: str, db_path: Path = None) -> dict | None:
    """获取文件的缓存元信息"""
    if db_path is None:
        db_path = get_cache_path()

    if not db_path.exists():
        return None

    normalized = normalize_path(file_path)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        """SELECT file_path, adapter, file_mtime_unix_ms, text_content_zstd
           FROM preproc_cache WHERE file_path = ? OR file_path LIKE ?""",
        (normalized, f"%{Path(file_path).name}")
    )
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    text = decompress_zstd(row[3])
    mtime_dt = datetime.fromtimestamp(row[2] / 1000) if row[2] else None

    total_chars = len(text)
    total_lines = text.count('\n') + 1
    total_pages = (total_chars + DEFAULT_CHUNK_SIZE - 1) // DEFAULT_CHUNK_SIZE

    return {
        "path": row[0],
        "adapter": row[1],
        "mtime": mtime_dt.strftime("%Y-%m-%d %H:%M:%S") if mtime_dt else "未知",
        "total_chars": total_chars,
        "total_lines": total_lines,
        "total_pages": total_pages,
        "page_size": DEFAULT_CHUNK_SIZE
    }


def get_cache_stats(db_path: Path = None) -> dict:
    """获取缓存统计信息"""
    if db_path is None:
        db_path = get_cache_path()

    if not db_path.exists():
        return {"error": "缓存数据库不存在"}

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(DISTINCT file_path) FROM preproc_cache")
    total = cursor.fetchone()[0]

    cursor.execute(
        "SELECT adapter, COUNT(DISTINCT file_path) FROM preproc_cache GROUP BY adapter ORDER BY COUNT(*) DESC"
    )
    by_adapter = cursor.fetchall()

    db_size = db_path.stat().st_size

    conn.close()

    return {
        "total_files": total,
        "by_adapter": dict(by_adapter),
        "db_size_mb": round(db_size / 1024 / 1024, 2),
        "db_path": str(db_path)
    }


def print_navigation_hint(meta: dict):
    """打印导航提示"""
    hints = []

    # 缩进模式
    if meta.get("mode") == "indent":
        hints.append(f"缩进模式: 行 {meta['start_line']}-{meta['end_line']}/{meta['total_lines']}")
        hints.append(f"提取 {meta['extracted_lines']} 行 (基准缩进: {meta['base_indent']})")
        if meta.get("has_more"):
            hints.append(f"继续: --line {meta['end_line']+1}")
    elif "page" in meta:
        hints.append(f"第 {meta['page']}/{meta['total_pages']} 页")
        if meta.get("has_prev"):
            hints.append(f"上一页: --page {meta['page']-1}")
        if meta.get("has_more"):
            hints.append(f"下一页: --page {meta['page']+1}")
    elif "start_line" in meta:
        hints.append(f"行 {meta['start_line']}-{meta['end_line']}/{meta['total_lines']}")
        if meta.get("has_more"):
            hints.append(f"继续: --line {meta['end_line']+1}")
    elif "keyword" in meta:
        hints.append(f"关键词 '{meta['keyword']}' 第 {meta['occurrence']}/{meta['total_matches']} 处")
        if meta['total_matches'] > meta['occurrence']:
            hints.append(f"下一处: --occur {meta['occurrence']+1}")
    else:
        hints.append(f"位置 {meta['start']}-{meta['end']}/{meta['total_chars']}")
        if meta.get("has_more"):
            hints.append(f"继续: --offset {meta['end']}")

    print(f"\n[导航] {' | '.join(hints)}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="从 rga 缓存读取文档文本（支持滑动分片）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
滑动分片读取示例:
  %(prog)s file.pdf                      默认读取（前 50K 字符）
  %(prog)s file.pdf --page 2             读取第 2 页
  %(prog)s file.pdf --around "摘要"       从"摘要"关键词位置读取
  %(prog)s file.pdf --around "结论" -o 2  从第 2 次出现的"结论"读取
  %(prog)s file.pdf --offset 50000       从第 50000 字符开始读取
  %(prog)s file.pdf --line 100           从第 100 行开始读取
  %(prog)s file.pdf --indent 100         从第 100 行开始提取代码块（按缩进）
  %(prog)s file.pdf --no-limit           读取全部（不限制）

格式化选项:
  %(prog)s file.pdf -n                   显示行号 (cat -n 格式)
  %(prog)s file.pdf --raw                禁用格式化（不截断长行）

其他命令:
  %(prog)s --list                        列出所有缓存文件
  %(prog)s --list .pdf                   列出 PDF 缓存
  %(prog)s --info file.pdf               显示文件信息和分页数
  %(prog)s --stats                       显示缓存统计
        """
    )

    parser.add_argument("file", nargs="?", help="要读取的文件路径")

    # 切片参数
    slice_group = parser.add_argument_group("滑动分片")
    slice_group.add_argument("--around", "-a", metavar="KEYWORD",
                            help="从关键词位置读取上下文")
    slice_group.add_argument("--occur", "-o", type=int, default=1, metavar="N",
                            help="关键词第 N 次出现 (默认: 1)")
    slice_group.add_argument("--page", "-p", type=int, metavar="N",
                            help="读取第 N 页 (每页 50K 字符)")
    slice_group.add_argument("--offset", type=int, metavar="N",
                            help="从第 N 个字符开始读取")
    slice_group.add_argument("--line", type=int, metavar="N",
                            help="从第 N 行开始读取")
    slice_group.add_argument("--indent", type=int, metavar="N",
                            help="从第 N 行开始按缩进提取代码块")
    slice_group.add_argument("--size", "-s", type=int, default=DEFAULT_CHUNK_SIZE, metavar="N",
                            help=f"分片大小 (默认: {DEFAULT_CHUNK_SIZE})")
    slice_group.add_argument("--lines", type=int, default=500, metavar="N",
                            help="按行读取时的行数 (默认: 500)")
    slice_group.add_argument("--no-limit", action="store_true",
                            help="读取全部内容（不分片）")

    # 格式化参数
    format_group = parser.add_argument_group("格式化选项")
    format_group.add_argument("-n", "--line-numbers", action="store_true",
                             help="显示行号 (cat -n 格式)")
    format_group.add_argument("--raw", action="store_true",
                             help="原始输出（不截断长行、不转换制表符）")
    format_group.add_argument("--max-line-len", type=int, default=MAX_LINE_LENGTH,
                             help=f"单行最大长度 (默认: {MAX_LINE_LENGTH})")

    # 其他参数
    other_group = parser.add_argument_group("其他命令")
    other_group.add_argument("--list", "-l", nargs="?", const="", metavar="PATTERN",
                            help="列出缓存文件")
    other_group.add_argument("--info", "-i", metavar="FILE",
                            help="显示文件信息")
    other_group.add_argument("--stats", action="store_true",
                            help="显示缓存统计")

    args = parser.parse_args()

    # 显示统计
    if args.stats:
        stats = get_cache_stats()
        if "error" in stats:
            print(stats["error"], file=sys.stderr)
            sys.exit(1)
        print(f"缓存路径: {stats['db_path']}")
        print(f"数据库大小: {stats['db_size_mb']} MB")
        print(f"缓存文件数: {stats['total_files']}")
        print("\n按适配器分类:")
        for adapter, count in stats['by_adapter'].items():
            print(f"  {adapter}: {count}")
        return

    # 列出文件
    if args.list is not None:
        files = list_cached_files(args.list if args.list else None)
        if not files:
            print("缓存为空或未找到匹配文件", file=sys.stderr)
            sys.exit(1)
        for path, adapter in files:
            print(f"[{adapter}] {path}")
        return

    # 显示元信息
    if args.info:
        info = get_cache_info(args.info)
        if info is None:
            print(f"缓存中未找到: {args.info}", file=sys.stderr)
            sys.exit(1)
        print(f"路径: {info['path']}")
        print(f"适配器: {info['adapter']}")
        print(f"修改时间: {info['mtime']}")
        print(f"总字符数: {info['total_chars']}")
        print(f"总行数: {info['total_lines']}")
        print(f"分页数: {info['total_pages']} (每页 {info['page_size']} 字符)")
        return

    # 读取文件内容
    if args.file:
        text = read_cache(args.file)
        if text is None:
            sys.exit(1)

        # 格式化选项
        do_format = not args.raw
        show_line_nums = args.line_numbers

        # 不限制模式
        if args.no_limit:
            if do_format:
                output = format_output(
                    text,
                    start_line=1,
                    show_line_numbers=show_line_nums,
                    truncate_long_lines=True,
                    expand_tabs=True
                )
            else:
                output = text
            print(output)
            print(f"\n[完整输出] {len(text)} 字符, {text.count(chr(10))+1} 行", file=sys.stderr)
            return

        # 选择切片方式
        start_line = 1  # 用于行号显示
        if args.around:
            content, meta = slice_around_keyword(
                text, args.around, args.size, args.occur
            )
            if "error" in meta:
                print(meta["error"], file=sys.stderr)
                sys.exit(1)
            # 计算起始行号（用于格式化输出）
            start_line = text[:meta['start']].count('\n') + 1
        elif args.indent:
            # 缩进模式
            content, meta = slice_by_indent(text, args.indent, max_lines=args.lines)
            if "error" in meta:
                print(meta["error"], file=sys.stderr)
                sys.exit(1)
            start_line = meta['start_line']
        elif args.page:
            content, meta = slice_by_page(text, args.page, args.size)
            if "error" in meta:
                print(meta["error"], file=sys.stderr)
                sys.exit(1)
            # 估算起始行号
            if args.page > 1:
                prev_content = text[:(args.page - 1) * args.size]
                start_line = prev_content.count('\n') + 1
        elif args.offset is not None:
            content, meta = slice_by_offset(text, args.offset, args.size)
            start_line = text[:meta['start']].count('\n') + 1
        elif args.line:
            content, meta = slice_by_lines(text, args.line, args.lines)
            if "error" in meta:
                print(meta["error"], file=sys.stderr)
                sys.exit(1)
            start_line = meta['start_line']
        else:
            # 默认：第一页
            content, meta = slice_by_page(text, 1, args.size)

        # 应用格式化
        if do_format:
            output = format_output(
                content,
                start_line=start_line,
                show_line_numbers=show_line_nums,
                truncate_long_lines=True,
                expand_tabs=True
            )
        else:
            output = content

        print(output)
        print_navigation_hint(meta)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
