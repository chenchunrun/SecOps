#!/usr/bin/env python3
"""
检测报告生成模块
支持JSON、CSV、HTML等多种格式
"""

import json
import csv
import os
from datetime import datetime
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)


class ReportGenerator:
    """检测报告生成器"""

    def __init__(self, config: dict = None):
        """
        初始化报告生成器

        Args:
            config: 配置字典
        """
        self.config = config or {}
        self.output_dir = self.config.get('output_dir', 'reports')
        os.makedirs(self.output_dir, exist_ok=True)

    def generate(
        self,
        detections: List[Dict],
        probe_results: List = None,
        formats: List[str] = None
    ) -> Dict[str, str]:
        """
        生成检测报告

        Args:
            detections: 检测结果列表
            probe_results: 原始探测结果（可选）
            formats: 输出格式列表

        Returns:
            生成的文件路径字典 {格式: 路径}
        """
        if formats is None:
            formats = self.config.get('formats', ['json', 'csv'])

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        generated_files = {}

        for fmt in formats:
            if fmt == 'json':
                file_path = self._generate_json(detections, probe_results, timestamp)
                generated_files['json'] = file_path

            elif fmt == 'csv':
                file_path = self._generate_csv(detections, timestamp)
                generated_files['csv'] = file_path

            elif fmt == 'html':
                file_path = self._generate_html(detections, timestamp)
                generated_files['html'] = file_path

        logger.info(f"报告生成完成: {list(generated_files.values())}")
        return generated_files

    def _generate_json(
        self,
        detections: List[Dict],
        probe_results: List,
        timestamp: str
    ) -> str:
        """生成JSON格式报告"""
        file_name = f"dns_detection_{timestamp}.json"
        file_path = os.path.join(self.output_dir, file_name)

        report = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'version': '1.0',
                'total_detections': len(detections)
            },
            'summary': self._generate_summary(detections),
            'detections': detections
        }

        # 可选：包含原始探测数据
        if probe_results and self.config.get('include_raw_data', False):
            report['raw_probe_results'] = [
                {
                    'domain': r.domain,
                    'dns_server': r.dns_server,
                    'method': r.method,
                    'is_cached': r.is_cached,
                    'timestamp': r.timestamp.isoformat(),
                    'authoritative_ttl': r.authoritative_ttl,
                    'cached_ttl': r.cached_ttl,
                    'error': r.error
                }
                for r in probe_results
            ]

        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)

        logger.info(f"JSON报告: {file_path}")
        return file_path

    def _generate_csv(self, detections: List[Dict], timestamp: str) -> str:
        """生成CSV格式报告"""
        file_name = f"dns_detection_{timestamp}.csv"
        file_path = os.path.join(self.output_dir, file_name)

        if not detections:
            logger.warning("无检测结果，跳过CSV生成")
            return file_path

        fieldnames = [
            'timestamp', 'domain', 'dns_server', 'severity',
            'category', 'cache_age_seconds', 'source'
        ]

        with open(file_path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for det in detections:
                ioc_info = det.get('ioc', {}) or {}
                writer.writerow({
                    'timestamp': det['timestamp'].isoformat() if isinstance(det['timestamp'], datetime) else det['timestamp'],
                    'domain': det['domain'],
                    'dns_server': det['dns_server'],
                    'severity': det['severity'],
                    'category': ioc_info.get('category', 'unknown'),
                    'cache_age_seconds': det.get('cache_age_seconds', ''),
                    'source': ioc_info.get('source', '')
                })

        logger.info(f"CSV报告: {file_path}")
        return file_path

    def _generate_html(self, detections: List[Dict], timestamp: str) -> str:
        """生成HTML格式报告"""
        file_name = f"dns_detection_{timestamp}.html"
        file_path = os.path.join(self.output_dir, file_name)

        summary = self._generate_summary(detections)

        html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNS缓存探测威胁检测报告</title>
    <style>
        body {{
            font-family: 'Microsoft YaHei', Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #e74c3c;
            padding-bottom: 10px;
        }}
        .summary {{
            background: #ecf0f1;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .summary-item {{
            display: inline-block;
            margin: 10px 20px 10px 0;
        }}
        .summary-label {{
            font-weight: bold;
            color: #555;
        }}
        .summary-value {{
            color: #e74c3c;
            font-size: 24px;
            font-weight: bold;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th {{
            background: #34495e;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        td {{
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }}
        tr:hover {{
            background: #f9f9f9;
        }}
        .severity-critical {{
            color: #c0392b;
            font-weight: bold;
        }}
        .severity-high {{
            color: #e67e22;
            font-weight: bold;
        }}
        .severity-medium {{
            color: #f39c12;
        }}
        .severity-low {{
            color: #27ae60;
        }}
        .footer {{
            margin-top: 30px;
            text-align: center;
            color: #7f8c8d;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>[*] DNS缓存探测威胁检测报告</h1>

        <div class="summary">
            <h2>检测摘要</h2>
            <div class="summary-item">
                <span class="summary-label">生成时间:</span>
                <span>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
            </div>
            <div class="summary-item">
                <span class="summary-label">威胁总数:</span>
                <span class="summary-value">{summary['total_detections']}</span>
            </div>
            <div class="summary-item">
                <span class="summary-label">Critical:</span>
                <span class="severity-critical">{summary['by_severity'].get('critical', 0)}</span>
            </div>
            <div class="summary-item">
                <span class="summary-label">High:</span>
                <span class="severity-high">{summary['by_severity'].get('high', 0)}</span>
            </div>
            <div class="summary-item">
                <span class="summary-label">Medium:</span>
                <span class="severity-medium">{summary['by_severity'].get('medium', 0)}</span>
            </div>
            <div class="summary-item">
                <span class="summary-label">Low:</span>
                <span class="severity-low">{summary['by_severity'].get('low', 0)}</span>
            </div>
        </div>

        <h2>检测详情</h2>
        <table>
            <thead>
                <tr>
                    <th>时间</th>
                    <th>威胁域名</th>
                    <th>DNS服务器</th>
                    <th>类别</th>
                    <th>严重程度</th>
                    <th>缓存年龄</th>
                </tr>
            </thead>
            <tbody>
"""

        for det in detections:
            ioc_info = det.get('ioc', {}) or {}
            timestamp_str = det['timestamp'].strftime('%H:%M:%S') if isinstance(det['timestamp'], datetime) else str(det['timestamp'])
            cache_age = f"{det.get('cache_age_seconds', 'N/A')}秒" if det.get('cache_age_seconds') else 'N/A'

            html_content += f"""
                <tr>
                    <td>{timestamp_str}</td>
                    <td><strong>{det['domain']}</strong></td>
                    <td>{det['dns_server']}</td>
                    <td>{ioc_info.get('category', 'unknown')}</td>
                    <td class="severity-{det['severity']}">{det['severity'].upper()}</td>
                    <td>{cache_age}</td>
                </tr>
"""

        html_content += """
            </tbody>
        </table>

        <div class="footer">
            <p>DNS缓存探测威胁检测系统 v1.0 | 基于三阶段检测架构</p>
        </div>
    </div>
</body>
</html>
"""

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        logger.info(f"HTML报告: {file_path}")
        return file_path

    def _generate_summary(self, detections: List[Dict]) -> Dict:
        """生成摘要统计"""
        summary = {
            'total_detections': len(detections),
            'by_severity': {},
            'by_category': {},
            'by_dns_server': {}
        }

        for det in detections:
            # 按严重程度统计
            severity = det['severity']
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1

            # 按类别统计
            ioc_info = det.get('ioc', {}) or {}
            category = ioc_info.get('category', 'unknown')
            summary['by_category'][category] = summary['by_category'].get(category, 0) + 1

            # 按DNS服务器统计
            dns_server = det['dns_server']
            summary['by_dns_server'][dns_server] = summary['by_dns_server'].get(dns_server, 0) + 1

        return summary


if __name__ == "__main__":
    # 测试代码
    logging.basicConfig(level=logging.INFO)

    # 模拟检测结果
    test_detections = [
        {
            'timestamp': datetime.now(),
            'domain': 'evil-c2.example.com',
            'dns_server': '10.0.0.53',
            'severity': 'high',
            'cache_age_seconds': 120,
            'ioc': {
                'category': 'c2',
                'source': 'test'
            }
        }
    ]

    reporter = ReportGenerator({'output_dir': 'reports'})
    reporter.generate(test_detections, formats=['json', 'csv', 'html'])
