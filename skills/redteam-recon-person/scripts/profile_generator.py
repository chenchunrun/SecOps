#!/usr/bin/env python3
"""
人物画像生成器 — 基于 OSINT 收集结果生成结构化目标档案。

用法:
    python3 profile_generator.py -i result.json -o profile.md
    python3 profile_generator.py -i result.json --risk-only
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path


def calculate_risk(profile_data: dict) -> dict:
    """根据收集到的信息计算风险评估分数。"""
    risk = {
        "privacy_awareness": "low",
        "security_habits": "unknown",
        "social_engineering_vulnerability": "high",
        "credential_exposure": "unknown",
        "score": 0,
    }

    score = 0

    # 社交媒体暴露
    social_count = len(profile_data.get("social_media", []))
    if social_count > 3:
        score += 20
        risk["privacy_awareness"] = "low"
    elif social_count > 0:
        score += 10
        risk["privacy_awareness"] = "medium"
    else:
        risk["privacy_awareness"] = "high"

    # 凭证泄露
    breaches = profile_data.get("breaches", [])
    if breaches:
        score += 30
        risk["credential_exposure"] = f"confirmed ({len(breaches)} breaches)"
        risk["security_habits"] = "poor" if len(breaches) > 2 else "moderate"

    # 用户名一致性
    usernames = len(profile_data.get("usernames", []))
    if usernames > 3:
        score += 15  # 高度一致的数字足迹更容易被追踪

    # 公开邮箱
    emails = profile_data.get("emails", [])
    if emails:
        score += 10

    # 职位/组织信息
    org_info = profile_data.get("organization", {})
    if org_info.get("role", "").lower() in ("ceo", "cto", "cfo", "cio", "manager", "admin"):
        score += 20  # 高价值目标
        risk["social_engineering_vulnerability"] = "critical"

    # 技术技能
    skills = profile_data.get("skills", [])
    tech_skills = [s for s in skills if any(k in s.lower() for k in ("python", "java", "devops", "cloud", "security"))]
    if tech_skills:
        score += 5  # 技术人员可能对技术钓鱼更有抵抗力
        risk["social_engineering_vulnerability"] = "medium"

    risk["score"] = min(score, 100)

    if score >= 70:
        risk["overall"] = "critical"
    elif score >= 50:
        risk["overall"] = "high"
    elif score >= 30:
        risk["overall"] = "medium"
    else:
        risk["overall"] = "low"

    return risk


def generate_attack_surface(profile_data: dict) -> list:
    """基于画像生成攻击面分析。"""
    attack_vectors = []

    emails = profile_data.get("emails", [])
    if emails:
        attack_vectors.append({
            "vector": "Email Phishing",
            "feasibility": "high",
            "basis": f"{len(emails)} email(s) discovered",
            "recommended_topics": ["IT updates", "Security alerts"] if any(
                "it" in str(profile_data.get("organization", {}).get("role", "")).lower()
                for _ in [1]
            ) else ["General business"],
        })

    breaches = profile_data.get("breaches", [])
    if breaches:
        attack_vectors.append({
            "vector": "Credential Stuffing",
            "feasibility": "high",
            "basis": f"{len(breaches)} breach(es) found",
            "recommended_action": "Check if leaked passwords match current corporate policy",
        })

    social = profile_data.get("social_media", [])
    if len(social) > 2:
        attack_vectors.append({
            "vector": "Social Media Impersonation",
            "feasibility": "medium",
            "basis": f"{len(social)} platforms with active presence",
            "recommended_action": "Create lookalike accounts for pretext attacks",
        })

    skills = profile_data.get("skills", [])
    if any("cloud" in s.lower() for s in skills):
        attack_vectors.append({
            "vector": "Cloud Service Phishing",
            "feasibility": "high",
            "basis": "Target works with cloud infrastructure",
            "recommended_topics": ["AWS/Azure alerts", "Docker/CI notifications"],
        })

    return attack_vectors


def generate_markdown(profile_data: dict, risk: dict, attack_surface: list) -> str:
    """生成 Markdown 格式的人物档案。"""
    lines = [
        f"# 目标安全评估档案",
        f"",
        f"> 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"> 评估工具: redteam-recon-person profile_generator v1.0",
        f"",
        f"## 风险摘要",
        f"",
        f"| 维度 | 评估 |",
        f"|------|------|",
        f"| 总体风险 | **{risk['overall'].upper()}** ({risk['score']}/100) |",
        f"| 隐私意识 | {risk['privacy_awareness']} |",
        f"| 安全习惯 | {risk['security_habits']} |",
        f"| 社工脆弱性 | {risk['social_engineering_vulnerability']} |",
        f"| 凭证暴露 | {risk['credential_exposure']} |",
        f"",
        f"## 基本信息",
        f"",
    ]

    org = profile_data.get("organization", {})
    if org:
        lines.append(f"| 字段 | 信息 |")
        lines.append(f"|------|------|")
        lines.append(f"| 姓名 | {profile_data.get('name', 'N/A')} |")
        lines.append(f"| 职位 | {org.get('role', 'N/A')} |")
        lines.append(f"| 组织 | {org.get('name', 'N/A')} |")
        lines.append(f"")

    # 社交媒体
    social = profile_data.get("social_media", [])
    if social:
        lines.append(f"## 社交媒体 ({len(social)} 平台)")
        lines.append(f"")
        lines.append(f"| 平台 | 用户名 | 来源 |")
        lines.append(f"|------|--------|------|")
        for s in social:
            lines.append(f"| {s.get('platform', '?')} | {s.get('username', '?')} | {s.get('source', '?')} |")
        lines.append(f"")

    # 攻击面
    if attack_surface:
        lines.append(f"## 攻击面分析")
        lines.append(f"")
        for av in attack_surface:
            lines.append(f"### {av['vector']}")
            lines.append(f"- 可行性: **{av['feasibility']}**")
            lines.append(f"- 依据: {av['basis']}")
            if "recommended_topics" in av:
                lines.append(f"- 推荐钓鱼主题: {', '.join(av['recommended_topics'])}")
            if "recommended_action" in av:
                lines.append(f"- 建议行动: {av['recommended_action']}")
            lines.append(f"")

    # MITRE ATT&CK 映射
    lines.append(f"## MITRE ATT&CK 映射")
    lines.append(f"")
    lines.append(f"| 战术 | 技术 | 场景 |")
    lines.append(f"|------|------|------|")
    mappings = [
        ("Reconnaissance", "T1589", "Gather Victim Identity Information"),
        ("Reconnaissance", "T1593.002", "Search Code Repositories"),
        ("Initial Access", "T1566.001", "Spearphishing Attachment"),
        ("Credential Access", "T1110", "Brute Force"),
        ("Credential Access", "T1552", "Unsecured Credentials"),
    ]
    for tactic, tech, name in mappings:
        lines.append(f"| {tactic} | {tech} | {name} |")
    lines.append(f"")

    lines.append(f"## IOC 采集清单")
    lines.append(f"")
    lines.append(f"| 类型 | 数量 | 格式 |")
    lines.append(f"|------|------|------|")
    lines.append(f"| 邮箱地址 | {len(profile_data.get('emails', []))} | email_addr |")
    lines.append(f"| 用户名 | {len(profile_data.get('usernames', []))} | username |")
    lines.append(f"| 社交媒体 | {len(profile_data.get('social_media', []))} | url |")
    lines.append(f"| 数据泄露 | {len(profile_data.get('breaches', []))} | breach_record |")
    lines.append(f"")

    lines.append(f"---")
    lines.append(f"*此报告仅限授权安全评估使用。*")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="人物画像生成器")
    parser.add_argument("-i", "--input", required=True, help="输入 JSON 文件 (person_recon.py 输出)")
    parser.add_argument("-o", "--output", help="输出 Markdown 文件路径")
    parser.add_argument("--risk-only", action="store_true", help="仅输出风险评估")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"错误: 输入文件不存在: {input_path}", file=sys.stderr)
        sys.exit(1)

    with open(input_path, "r", encoding="utf-8") as f:
        profile_data = json.load(f)

    risk = calculate_risk(profile_data)
    attack_surface = generate_attack_surface(profile_data)

    if args.risk_only:
        print(json.dumps(risk, indent=2, ensure_ascii=False))
        return

    md_report = generate_markdown(profile_data, risk, attack_surface)

    if args.output:
        Path(args.output).write_text(md_report, encoding="utf-8")
        print(f"✅ 档案已生成: {args.output}")
    else:
        print(md_report)


if __name__ == "__main__":
    main()
