#!/usr/bin/env python3
"""
DNS缓存探测核心模块
实现RD=0探测和TTL对比两种方法
"""

import dns.message
import dns.query
import dns.flags
import dns.rdatatype
import dns.resolver
from dataclasses import dataclass
from typing import Optional, List, Tuple
from datetime import datetime
import logging
import time

logger = logging.getLogger(__name__)


@dataclass
class ProbeResult:
    """DNS探测结果数据类"""
    domain: str
    dns_server: str
    method: str  # 'rd0' 或 'ttl_compare'
    timestamp: datetime

    # RD=0探测结果
    rd0_response: Optional[bool] = None  # True=有响应, False=无响应
    rd0_ttl: Optional[int] = None

    # TTL对比结果
    authoritative_ttl: Optional[int] = None
    cached_ttl: Optional[int] = None
    ttl_difference: Optional[int] = None

    # 判定结果
    is_cached: bool = False
    cache_age_seconds: Optional[int] = None

    # 原始数据
    raw_response: Optional[str] = None
    error: Optional[str] = None


class DNSProbe:
    """DNS缓存探测器"""

    def __init__(self, timeout: int = 3):
        """
        初始化DNS探测器

        Args:
            timeout: DNS查询超时时间（秒）
        """
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def probe_rd0(self, domain: str, dns_server: str) -> ProbeResult:
        """
        方法1: RD=0 非递归查询探测

        原理：
        - 如果域名已缓存，DNS服务器会直接返回（即使RD=0）
        - 如果域名未缓存，DNS服务器返回REFUSED/SERVFAIL或空响应

        Args:
            domain: 待探测域名
            dns_server: 目标DNS服务器IP

        Returns:
            ProbeResult对象
        """
        result = ProbeResult(
            domain=domain,
            dns_server=dns_server,
            method='rd0',
            timestamp=datetime.now()
        )

        try:
            # 构造RD=0查询
            query = dns.message.make_query(domain, dns.rdatatype.A)
            query.flags &= ~dns.flags.RD  # 清除RD标志位

            # 发送查询
            response = dns.query.udp(query, dns_server, timeout=self.timeout)
            result.raw_response = str(response)

            # 解析响应
            if response.answer:
                # 有ANSWER SECTION → 缓存命中
                result.rd0_response = True
                result.is_cached = True

                # 提取TTL
                for rrset in response.answer:
                    result.rd0_ttl = rrset.ttl
                    break

                logger.debug(f"[RD=0] {domain} @ {dns_server}: 缓存命中 (TTL={result.rd0_ttl})")

            elif response.rcode() == dns.rcode.REFUSED:
                # REFUSED → 未缓存（服务器拒绝非递归查询）
                result.rd0_response = False
                result.is_cached = False
                logger.debug(f"[RD=0] {domain} @ {dns_server}: 未缓存 (REFUSED)")

            elif response.rcode() == dns.rcode.SERVFAIL:
                # SERVFAIL → 可能未缓存
                result.rd0_response = False
                result.is_cached = False
                logger.debug(f"[RD=0] {domain} @ {dns_server}: 未缓存 (SERVFAIL)")

            else:
                # 其他情况（NXDOMAIN等）
                result.rd0_response = False
                result.is_cached = False
                logger.debug(f"[RD=0] {domain} @ {dns_server}: 未缓存 (rcode={response.rcode()})")

        except dns.exception.Timeout:
            result.error = "查询超时"
            logger.warning(f"[RD=0] {domain} @ {dns_server}: 超时")

        except Exception as e:
            result.error = str(e)
            logger.error(f"[RD=0] {domain} @ {dns_server}: 错误 - {e}")

        return result

    def get_authoritative_ttl(self, domain: str, auth_dns: str = "223.5.5.5", timeout: Optional[int] = None) -> Optional[int]:
        """
        获取域名的权威TTL（从公共DNS查询）

        关键：必须先获取权威TTL，避免探测污染缓存

        Args:
            domain: 域名
            auth_dns: 权威DNS服务器（默认阿里云DNS）
            timeout: 查询超时时间（秒），None则使用默认值

        Returns:
            TTL值（秒），失败返回None
        """
        timeout = timeout if timeout is not None else self.timeout

        try:
            # 使用RD=0查询公共DNS（避免污染其缓存）
            query = dns.message.make_query(domain, dns.rdatatype.A)
            query.flags &= ~dns.flags.RD

            response = dns.query.udp(query, auth_dns, timeout=timeout)

            if response.answer:
                for rrset in response.answer:
                    ttl = rrset.ttl
                    logger.debug(f"[权威TTL] {domain}: {ttl}秒 (来源: {auth_dns})")
                    return ttl

            # 如果RD=0无响应，使用正常查询
            query.flags |= dns.flags.RD
            response = dns.query.udp(query, auth_dns, timeout=timeout)

            if response.answer:
                for rrset in response.answer:
                    return rrset.ttl

        except Exception as e:
            logger.error(f"[权威TTL] {domain}: 获取失败 - {e}")

        return None

    def probe_ttl_compare(
        self,
        domain: str,
        dns_server: str,
        auth_dns: str = "223.5.5.5",
        cached_auth_ttl: Optional[int] = None
    ) -> ProbeResult:
        """
        方法2: TTL对比探测

        原理：
        1. 先从公共DNS获取权威TTL（original_ttl）
        2. 再从企业DNS用RD=0查询（避免污染）
        3. 如果企业DNS有响应且TTL < original_ttl → 缓存命中

        Args:
            domain: 待探测域名
            dns_server: 目标DNS服务器IP
            auth_dns: 权威DNS服务器（默认阿里云）
            cached_auth_ttl: 预获取的权威TTL（可选，用于性能优化）

        Returns:
            ProbeResult对象
        """
        result = ProbeResult(
            domain=domain,
            dns_server=dns_server,
            method='ttl_compare',
            timestamp=datetime.now()
        )

        # Step 1: 获取权威TTL（必须先做！）
        # 优先使用缓存的权威TTL（性能优化）
        if cached_auth_ttl is not None:
            original_ttl = cached_auth_ttl
        else:
            original_ttl = self.get_authoritative_ttl(domain, auth_dns)
            if original_ttl is None:
                result.error = "无法获取权威TTL"
                return result

        result.authoritative_ttl = original_ttl

        # Step 2: RD=0探测企业DNS
        try:
            query = dns.message.make_query(domain, dns.rdatatype.A)
            query.flags &= ~dns.flags.RD

            response = dns.query.udp(query, dns_server, timeout=self.timeout)
            result.raw_response = str(response)

            if response.answer:
                for rrset in response.answer:
                    result.cached_ttl = rrset.ttl
                    break

                # Step 3: TTL对比
                if result.cached_ttl < original_ttl:
                    result.is_cached = True
                    result.ttl_difference = original_ttl - result.cached_ttl
                    result.cache_age_seconds = result.ttl_difference

                    logger.info(
                        f"[TTL对比] {domain} @ {dns_server}: 缓存命中! "
                        f"权威TTL={original_ttl}, 缓存TTL={result.cached_ttl}, "
                        f"差异={result.ttl_difference}秒"
                    )
                else:
                    result.is_cached = False
                    result.ttl_difference = original_ttl - result.cached_ttl
                    logger.debug(
                        f"[TTL对比] {domain} @ {dns_server}: 未缓存 "
                        f"(TTL差异={result.ttl_difference})"
                    )
            else:
                result.is_cached = False
                logger.debug(f"[TTL对比] {domain} @ {dns_server}: 无响应")

        except dns.exception.Timeout:
            result.error = "查询超时"
            logger.warning(f"[TTL对比] {domain} @ {dns_server}: 超时")

        except Exception as e:
            result.error = str(e)
            logger.error(f"[TTL对比] {domain} @ {dns_server}: 错误 - {e}")

        return result

    def probe_multiple(
        self,
        domain: str,
        dns_server: str,
        repeats: int = 10,
        auth_dns: str = "223.5.5.5"
    ) -> List[ProbeResult]:
        """
        多次探测同一域名（提高准确性）

        Args:
            domain: 域名
            dns_server: 目标DNS服务器
            repeats: 重复次数
            auth_dns: 权威DNS

        Returns:
            ProbeResult列表
        """
        results = []

        # 先获取一次权威TTL
        original_ttl = self.get_authoritative_ttl(domain, auth_dns)
        if original_ttl is None:
            logger.error(f"无法获取 {domain} 的权威TTL，跳过探测")
            return results

        for i in range(repeats):
            result = self.probe_rd0(domain, dns_server)
            results.append(result)

            # 短暂延迟避免被限流
            if i < repeats - 1:
                time.sleep(0.1)

        return results

    def check_rd0_support(self, dns_server: str) -> bool:
        """
        检测DNS服务器是否支持RD=0（不忽略RD标志）

        方法：查询一个随机不存在的域名
        - 如果返回结果 → 服务器忽略RD=0（不支持）
        - 如果返回REFUSED/SERVFAIL → 服务器支持RD=0

        Args:
            dns_server: DNS服务器IP

        Returns:
            True=支持, False=不支持
        """
        import uuid
        test_domain = f"test-{uuid.uuid4()}.example.invalid"

        try:
            query = dns.message.make_query(test_domain, dns.rdatatype.A)
            query.flags &= ~dns.flags.RD

            response = dns.query.udp(query, dns_server, timeout=self.timeout)

            if response.answer:
                # 有响应 → 服务器忽略了RD=0标志
                logger.warning(
                    f"DNS服务器 {dns_server} 不支持RD=0 "
                    f"(查询不存在域名返回了结果)"
                )
                return False
            else:
                # 无响应/REFUSED → 支持RD=0
                logger.info(f"DNS服务器 {dns_server} 支持RD=0")
                return True

        except Exception as e:
            logger.error(f"检测RD=0支持失败: {e}")
            return False


def analyze_probe_results(results: List[ProbeResult]) -> dict:
    """
    分析多次探测结果，给出综合判断

    Args:
        results: ProbeResult列表

    Returns:
        分析结果字典
    """
    if not results:
        return {"status": "error", "message": "无探测结果"}

    total = len(results)
    cached_count = sum(1 for r in results if r.is_cached)
    error_count = sum(1 for r in results if r.error)

    cache_rate = cached_count / total if total > 0 else 0

    analysis = {
        "domain": results[0].domain,
        "dns_server": results[0].dns_server,
        "total_probes": total,
        "cached_count": cached_count,
        "error_count": error_count,
        "cache_rate": cache_rate,
        "is_cached": cache_rate >= 0.7,  # 70%一致性阈值
        "confidence": cache_rate if cached_count > 0 else (1 - cache_rate)
    }

    # 计算平均缓存年龄
    ages = [r.cache_age_seconds for r in results if r.cache_age_seconds]
    if ages:
        analysis["avg_cache_age_seconds"] = sum(ages) / len(ages)

    return analysis
