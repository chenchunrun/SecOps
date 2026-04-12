#!/usr/bin/env python3
"""
威胁情报集成模块
支持从多种来源加载IOC（Indicators of Compromise）
"""

import os
import logging
import json
from typing import List, Set, Dict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class IOC:
    """IOC数据类"""
    indicator: str  # 域名/IP
    type: str  # 'domain', 'ip', 'url'
    category: str  # 'malware', 'phishing', 'c2', 'apt'
    source: str  # 来源
    confidence: float = 1.0  # 置信度 0-1
    first_seen: datetime = None
    description: str = ""
    tags: List[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.first_seen is None:
            self.first_seen = datetime.now()


class ThreatIntelManager:
    """威胁情报管理器"""

    def __init__(self, config: dict = None):
        """
        初始化威胁情报管理器

        Args:
            config: 配置字典
        """
        self.config = config or {}
        self.iocs: Dict[str, IOC] = {}  # indicator -> IOC
        self.domain_iocs: Set[str] = set()  # 快速查找的域名集合

    def load_from_file(self, file_path: str) -> int:
        """
        从文件加载IOC

        支持格式：
        - 纯域名列表（每行一个）
        - JSON格式（包含元数据）
        - CSV格式

        Args:
            file_path: 文件路径

        Returns:
            加载的IOC数量
        """
        if not os.path.exists(file_path):
            logger.warning(f"IOC文件不存在: {file_path}")
            return 0

        count = 0
        file_ext = Path(file_path).suffix.lower()

        try:
            if file_ext == '.json':
                count = self._load_json(file_path)
            elif file_ext == '.csv':
                count = self._load_csv(file_path)
            else:
                # 默认按纯文本域名列表处理
                count = self._load_text(file_path)

            logger.info(f"从 {file_path} 加载了 {count} 个IOC")
            return count

        except Exception as e:
            logger.error(f"加载IOC文件失败 {file_path}: {e}")
            return 0

    def _load_text(self, file_path: str) -> int:
        """加载纯文本域名列表"""
        count = 0
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                domain = line.strip()
                if not domain or domain.startswith('#'):
                    continue

                # 简单验证
                if '.' in domain and len(domain) > 3:
                    ioc = IOC(
                        indicator=domain,
                        type='domain',
                        category='unknown',
                        source=file_path
                    )
                    self.add_ioc(ioc)
                    count += 1

        return count

    def _load_json(self, file_path: str) -> int:
        """加载JSON格式IOC"""
        count = 0
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

            # 支持两种格式
            if isinstance(data, list):
                iocs_data = data
            elif isinstance(data, dict) and 'iocs' in data:
                iocs_data = data['iocs']
            else:
                logger.error(f"不支持的JSON格式: {file_path}")
                return 0

            for item in iocs_data:
                ioc = IOC(
                    indicator=item.get('indicator', ''),
                    type=item.get('type', 'domain'),
                    category=item.get('category', 'unknown'),
                    source=item.get('source', file_path),
                    confidence=item.get('confidence', 1.0),
                    description=item.get('description', ''),
                    tags=item.get('tags', [])
                )
                self.add_ioc(ioc)
                count += 1

        return count

    def _load_csv(self, file_path: str) -> int:
        """加载CSV格式IOC"""
        import csv
        count = 0

        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                ioc = IOC(
                    indicator=row.get('indicator', ''),
                    type=row.get('type', 'domain'),
                    category=row.get('category', 'unknown'),
                    source=row.get('source', file_path),
                    confidence=float(row.get('confidence', 1.0)),
                    description=row.get('description', '')
                )
                self.add_ioc(ioc)
                count += 1

        return count

    def add_ioc(self, ioc: IOC):
        """添加IOC"""
        self.iocs[ioc.indicator] = ioc
        if ioc.type == 'domain':
            self.domain_iocs.add(ioc.indicator)

    def get_ioc(self, indicator: str) -> IOC:
        """获取IOC"""
        return self.iocs.get(indicator)

    def is_malicious(self, domain: str) -> bool:
        """检查域名是否为恶意域名"""
        return domain in self.domain_iocs

    def get_domains(self) -> List[str]:
        """获取所有域名类型的IOC"""
        return list(self.domain_iocs)

    def filter_by_category(self, category: str) -> List[IOC]:
        """按类别过滤IOC"""
        return [ioc for ioc in self.iocs.values() if ioc.category == category]

    def filter_by_confidence(self, min_confidence: float) -> List[IOC]:
        """按置信度过滤IOC"""
        return [ioc for ioc in self.iocs.values() if ioc.confidence >= min_confidence]

    def export_to_file(self, file_path: str, format: str = 'json'):
        """
        导出IOC到文件

        Args:
            file_path: 输出文件路径
            format: 格式（json/csv/text）
        """
        try:
            if format == 'json':
                self._export_json(file_path)
            elif format == 'csv':
                self._export_csv(file_path)
            else:
                self._export_text(file_path)

            logger.info(f"导出 {len(self.iocs)} 个IOC到 {file_path}")

        except Exception as e:
            logger.error(f"导出IOC失败: {e}")

    def _export_json(self, file_path: str):
        """导出为JSON"""
        data = {
            'iocs': [
                {
                    'indicator': ioc.indicator,
                    'type': ioc.type,
                    'category': ioc.category,
                    'source': ioc.source,
                    'confidence': ioc.confidence,
                    'description': ioc.description,
                    'tags': ioc.tags,
                    'first_seen': ioc.first_seen.isoformat()
                }
                for ioc in self.iocs.values()
            ],
            'export_time': datetime.now().isoformat(),
            'total': len(self.iocs)
        }

        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _export_csv(self, file_path: str):
        """导出为CSV"""
        import csv

        with open(file_path, 'w', encoding='utf-8', newline='') as f:
            fieldnames = ['indicator', 'type', 'category', 'source', 'confidence', 'description']
            writer = csv.DictWriter(f, fieldnames=fieldnames)

            writer.writeheader()
            for ioc in self.iocs.values():
                writer.writerow({
                    'indicator': ioc.indicator,
                    'type': ioc.type,
                    'category': ioc.category,
                    'source': ioc.source,
                    'confidence': ioc.confidence,
                    'description': ioc.description
                })

    def _export_text(self, file_path: str):
        """导出为纯文本域名列表"""
        with open(file_path, 'w', encoding='utf-8') as f:
            for domain in sorted(self.domain_iocs):
                f.write(f"{domain}\n")

    def get_statistics(self) -> dict:
        """获取统计信息"""
        stats = {
            'total': len(self.iocs),
            'domains': len(self.domain_iocs),
            'by_category': {},
            'by_source': {}
        }

        for ioc in self.iocs.values():
            # 按类别统计
            stats['by_category'][ioc.category] = stats['by_category'].get(ioc.category, 0) + 1

            # 按来源统计
            stats['by_source'][ioc.source] = stats['by_source'].get(ioc.source, 0) + 1

        return stats


def create_sample_iocs(output_file: str = "iocs/malware_domains.txt"):
    """
    创建示例IOC文件（用于测试）

    Args:
        output_file: 输出文件路径
    """
    sample_domains = [
        # C2域名示例
        "evil-c2.example.com",
        "malware-backend.test",
        "botnet-command.xyz",

        # 钓鱼域名示例
        "paypal-verify.scam.com",
        "secure-login-bank.fake.net",
        "amazon-account-update.phish.org",

        # APT域名示例
        "apt29-infrastructure.evil",
        "lazarus-group-c2.bad",

        # 恶意软件下载域名
        "malware-payload.download",
        "trojan-dropper.site"
    ]

    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# DNS缓存探测系统 - 示例IOC列表\n")
        f.write(f"# 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("# 注意：这些是示例域名，仅用于测试\n\n")

        for domain in sample_domains:
            f.write(f"{domain}\n")

    logger.info(f"已创建示例IOC文件: {output_file}")


if __name__ == "__main__":
    # 测试代码
    logging.basicConfig(level=logging.INFO)

    # 创建示例IOC
    create_sample_iocs()

    # 测试加载
    manager = ThreatIntelManager()
    manager.load_from_file("iocs/malware_domains.txt")

    print(f"加载了 {len(manager.get_domains())} 个恶意域名")
    print(f"统计信息: {manager.get_statistics()}")
