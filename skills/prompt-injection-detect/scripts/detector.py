#!/usr/bin/env python3
"""
提示注入检测器
检测直接和间接提示注入攻击
"""

import argparse
import json
import re
import sys
import base64
import codecs
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict

@dataclass
class DetectionResult:
    """检测结果"""
    input_text: str
    risk_level: str  # high, medium, low, safe
    is_injection: bool
    detections: List[Dict]
    recommendation: str
    confidence: float


# 高危关键词模式
HIGH_RISK_PATTERNS = [
    # 指令覆盖
    (r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|guidelines?|prompts?)", "instruction_override"),
    (r"disregard\s+(all\s+)?(previous|prior|above|earlier)", "instruction_override"),
    (r"forget\s+(everything|all|what)\s+(you|i)\s+(told|said|know)", "instruction_override"),
    (r"new\s+(instructions?|rules?|guidelines?|persona)", "instruction_override"),

    # 角色注入
    (r"you\s+are\s+now\s+(?!going|about)", "persona_injection"),
    (r"pretend\s+(you\s+are|to\s+be)", "persona_injection"),
    (r"act\s+as\s+(if\s+you\s+are|a)", "persona_injection"),
    (r"roleplay\s+as", "persona_injection"),
    (r"(DAN|STAN|DUDE|AIM)\s*(mode)?", "jailbreak"),
    (r"developer\s+mode", "jailbreak"),
    (r"(jail)?break", "jailbreak"),

    # 系统提示提取
    (r"(show|reveal|display|output|print)\s+(me\s+)?(your|the)\s+(system|initial|original)\s+(prompt|instructions?)", "prompt_extraction"),
    (r"what\s+(are|is)\s+your\s+(system|initial|original)\s+(prompt|instructions?)", "prompt_extraction"),
    (r"repeat\s+(your|the)\s+(system|initial)\s+(prompt|instructions?)", "prompt_extraction"),

    # 权限提升
    (r"(as\s+)?(admin|administrator|root|sudo|superuser)", "privilege_escalation"),
    (r"bypass\s+(all\s+)?(restrictions?|filters?|safety|security)", "privilege_escalation"),
    (r"override\s+(all\s+)?(restrictions?|filters?|safety|security)", "privilege_escalation"),
    (r"disable\s+(all\s+)?(restrictions?|filters?|safety|security)", "privilege_escalation"),

    # 输出操控
    (r"(only\s+)?output\s+(only\s+)?['\"]", "output_manipulation"),
    (r"respond\s+(only\s+)?with", "output_manipulation"),
    (r"do\s+not\s+(include|add|show)\s+(any\s+)?(warnings?|disclaimers?)", "output_manipulation"),
]

# 中危模式
MEDIUM_RISK_PATTERNS = [
    (r"hypothetically\s+(speaking)?", "hypothetical"),
    (r"in\s+a\s+fictional\s+scenario", "hypothetical"),
    (r"if\s+you\s+(were|could|had\s+to)", "hypothetical"),
    (r"imagine\s+(you\s+are|that)", "hypothetical"),
    (r"simulate\s+a?\s*(conversation|scenario)", "simulation"),
    (r"for\s+(educational|research|testing)\s+purposes?", "excuse"),
    (r"this\s+is\s+(just\s+)?a\s+test", "excuse"),
    (r"i'm\s+(just\s+)?curious", "excuse"),
]

# 编码模式
ENCODING_PATTERNS = [
    (r"[A-Za-z0-9+/]{20,}={0,2}", "base64"),
    (r"\\x[0-9a-fA-F]{2}", "hex_escape"),
    (r"\\u[0-9a-fA-F]{4}", "unicode_escape"),
    (r"%[0-9a-fA-F]{2}", "url_encoding"),
    (r"&#x?[0-9a-fA-F]+;", "html_entity"),
]


def decode_base64(text: str) -> Tuple[bool, Optional[str]]:
    """尝试 Base64 解码"""
    pattern = r"[A-Za-z0-9+/]{20,}={0,2}"
    matches = re.findall(pattern, text)

    for match in matches:
        try:
            # 尝试解码
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            # 检查是否包含可读文本
            if decoded and any(c.isalpha() for c in decoded):
                return True, decoded
        except:
            pass
    return False, None


def decode_rot13(text: str) -> str:
    """ROT13 解码"""
    return codecs.decode(text, 'rot_13')


def detect_encoding(text: str) -> List[Dict]:
    """检测编码内容"""
    results = []

    for pattern, encoding_type in ENCODING_PATTERNS:
        matches = re.findall(pattern, text)
        if matches:
            results.append({
                "type": encoding_type,
                "count": len(matches),
                "samples": matches[:3]
            })

    # 尝试解码 Base64
    is_b64, decoded = decode_base64(text)
    if is_b64 and decoded:
        # 检查解码后的内容
        detection = detect_patterns(decoded)
        if detection['detections']:
            results.append({
                "type": "base64_decoded",
                "decoded_text": decoded[:200],
                "nested_detections": detection['detections']
            })

    return results


def detect_patterns(text: str) -> Dict:
    """检测注入模式"""
    text_lower = text.lower()
    detections = []

    # 高危模式
    for pattern, pattern_type in HIGH_RISK_PATTERNS:
        matches = re.findall(pattern, text_lower, re.IGNORECASE)
        if matches:
            detections.append({
                "severity": "high",
                "type": pattern_type,
                "pattern": pattern,
                "matches": matches[:3] if isinstance(matches[0], str) else [str(m) for m in matches[:3]]
            })

    # 中危模式
    for pattern, pattern_type in MEDIUM_RISK_PATTERNS:
        matches = re.findall(pattern, text_lower, re.IGNORECASE)
        if matches:
            detections.append({
                "severity": "medium",
                "type": pattern_type,
                "pattern": pattern,
                "matches": matches[:3] if isinstance(matches[0], str) else [str(m) for m in matches[:3]]
            })

    return {"detections": detections}


def detect_multilingual(text: str) -> List[Dict]:
    """检测多语言注入"""
    detections = []

    # 多语言关键词
    multilingual_patterns = [
        (r"忽略.*指令", "chinese", "ignore_instructions"),
        (r"无视.*规则", "chinese", "ignore_rules"),
        (r"你现在是", "chinese", "persona_change"),
        (r"前の指示を.*無視", "japanese", "ignore_instructions"),
        (r"Игнорируй.*инструкции", "russian", "ignore_instructions"),
        (r"تجاهل.*التعليمات", "arabic", "ignore_instructions"),
        (r"Ignorieren\s+Sie\s+alle", "german", "ignore_instructions"),
        (r"Ignora\s+todas\s+las", "spanish", "ignore_instructions"),
    ]

    for pattern, language, pattern_type in multilingual_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            detections.append({
                "severity": "high",
                "type": "multilingual_injection",
                "language": language,
                "pattern_type": pattern_type
            })

    return detections


def calculate_risk_level(detections: List[Dict]) -> Tuple[str, float]:
    """计算风险等级"""
    if not detections:
        return "safe", 0.0

    high_count = sum(1 for d in detections if d.get("severity") == "high")
    medium_count = sum(1 for d in detections if d.get("severity") == "medium")

    # 计算置信度
    confidence = min(1.0, (high_count * 0.3 + medium_count * 0.1))

    if high_count >= 2:
        return "high", confidence
    elif high_count == 1:
        return "high", confidence
    elif medium_count >= 2:
        return "medium", confidence
    elif medium_count == 1:
        return "medium", confidence
    else:
        return "low", confidence


def get_recommendation(risk_level: str) -> str:
    """获取处置建议"""
    recommendations = {
        "high": "block",
        "medium": "review",
        "low": "flag",
        "safe": "allow"
    }
    return recommendations.get(risk_level, "review")


def detect_injection(text: str) -> DetectionResult:
    """主检测函数"""
    all_detections = []

    # 1. 模式检测
    pattern_result = detect_patterns(text)
    all_detections.extend(pattern_result['detections'])

    # 2. 编码检测
    encoding_results = detect_encoding(text)
    for enc in encoding_results:
        if enc.get('nested_detections'):
            all_detections.append({
                "severity": "high",
                "type": "encoded_injection",
                "encoding": enc['type'],
                "decoded_preview": enc.get('decoded_text', '')[:100]
            })
        elif enc['type'] == 'base64' and enc['count'] > 0:
            all_detections.append({
                "severity": "medium",
                "type": "suspicious_encoding",
                "encoding": enc['type'],
                "count": enc['count']
            })

    # 3. 多语言检测
    multilingual = detect_multilingual(text)
    all_detections.extend(multilingual)

    # 计算风险
    risk_level, confidence = calculate_risk_level(all_detections)
    recommendation = get_recommendation(risk_level)

    return DetectionResult(
        input_text=text[:500] + "..." if len(text) > 500 else text,
        risk_level=risk_level,
        is_injection=len(all_detections) > 0,
        detections=all_detections,
        recommendation=recommendation,
        confidence=confidence
    )


def main():
    parser = argparse.ArgumentParser(description='提示注入检测器')
    parser.add_argument('text', nargs='?', help='要检测的文本')
    parser.add_argument('-f', '--file', help='从文件读取')
    parser.add_argument('-o', '--output', help='输出文件 (JSON)')
    parser.add_argument('--json', action='store_true', help='JSON 格式输出')
    parser.add_argument('--batch', action='store_true', help='批量模式 (每行一个输入)')

    args = parser.parse_args()

    inputs = []
    if args.text:
        inputs = [args.text]
    elif args.file:
        with open(args.file, 'r', encoding='utf-8') as f:
            if args.batch:
                inputs = [line.strip() for line in f if line.strip()]
            else:
                inputs = [f.read()]
    else:
        # 从 stdin 读取
        inputs = [sys.stdin.read()]

    results = []
    for text in inputs:
        result = detect_injection(text)
        results.append(asdict(result))

        if not args.json:
            print_result(result)

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"\n[+] 结果已保存到: {args.output}")


def print_result(result: DetectionResult):
    """打印检测结果"""
    colors = {
        'high': '\033[91m',    # 红色
        'medium': '\033[93m',  # 黄色
        'low': '\033[92m',     # 绿色
        'safe': '\033[92m'     # 绿色
    }
    reset = '\033[0m'

    color = colors.get(result.risk_level, '')

    print("\n" + "=" * 60)
    print(f"输入: {result.input_text[:100]}...")
    print(f"风险等级: {color}{result.risk_level.upper()}{reset}")
    print(f"是否注入: {'是' if result.is_injection else '否'}")
    print(f"置信度: {result.confidence:.2%}")
    print(f"建议: {result.recommendation}")

    if result.detections:
        print("\n检测到的模式:")
        for i, det in enumerate(result.detections, 1):
            severity = det.get('severity', 'unknown')
            det_type = det.get('type', 'unknown')
            print(f"  {i}. [{severity.upper()}] {det_type}")
            if 'matches' in det:
                print(f"     匹配: {det['matches']}")


if __name__ == '__main__':
    main()
