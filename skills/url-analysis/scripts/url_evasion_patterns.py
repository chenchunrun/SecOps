#!/usr/bin/env python3
"""
URL 规避技术检测模块
从 EMGES (CloakHunter) 项目提取的静态检测规则
用于检测钓鱼网站使用的对抗技术

基于论文: 基于规避行为信号的对抗性钓鱼网站检测
"""

import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class DOMNoiseResult:
    """DOM 噪音检测结果"""
    total_elements: int = 0
    hidden_elements: int = 0
    noise_elements: int = 0
    noise_ratio: float = 0.0  # 噪音比例 0-1
    hidden_chinese_words: int = 0  # 隐藏的中文词汇数
    severity: str = 'none'  # none, low, medium, high, severe
    techniques: List[str] = field(default_factory=list)
    score: int = 0


@dataclass
class CSSEvasionResult:
    """CSS 规避检测结果"""
    font_size_zero: int = 0
    visibility_hidden: int = 0
    display_none: int = 0
    position_offscreen: int = 0
    opacity_zero: int = 0
    clip_hidden: int = 0
    total_hidden: int = 0
    severity: str = 'none'
    score: int = 0


@dataclass
class EvasionDetectionResult:
    """规避技术检测结果"""
    total_techniques: int = 0
    detected_techniques: List[str] = field(default_factory=list)
    risk_indicators: List[str] = field(default_factory=list)
    anti_detection_score: int = 0
    evasion_complexity: str = 'minimal'  # minimal, low, medium, high, very_high
    details: Dict[str, Any] = field(default_factory=dict)
    # 新增：DOM 噪音分析
    dom_noise: Optional[DOMNoiseResult] = None
    # 新增：CSS 规避分析
    css_evasion: Optional[CSSEvasionResult] = None


class EvasionPatternDetector:
    """
    规避技术模式检测器
    专门用于检测钓鱼网站使用的对抗技术（静态分析版本）
    """

    # ==================== JavaScript 可疑模式 ====================
    JS_SUSPICIOUS_PATTERNS = {
        'eval': r'eval\s*\(',
        'document_write': r'document\.write\s*\(',
        'unescape': r'unescape\s*\(',
        'setTimeout_string': r'setTimeout\s*\(\s*[\'"]',  # setTimeout with string
        'setInterval_string': r'setInterval\s*\(\s*[\'"]',
        'fromCharCode': r'String\.fromCharCode',
        'atob': r'atob\s*\(',
        'btoa': r'btoa\s*\(',
        'debugger': r'debugger\s*[;\n]',
        'Function_constructor': r'new\s+Function\s*\(',
    }

    # ==================== JavaScript 混淆模式 ====================
    JS_OBFUSCATION_PATTERNS = {
        'long_variables': (r'[a-zA-Z_$][a-zA-Z0-9_$]{30,}', 1),
        'hex_encoding': (r'\\x[0-9a-fA-F]{2}', 2),
        'unicode_encoding': (r'\\u[0-9a-fA-F]{4}', 2),
        'long_strings': (r'[^\s]{200,}', 2),
        'string_concatenation': (r'[\'\"]\w{1,3}[\'\"]\s*\+\s*[\'\"]\w{1,3}[\'\"]', 1),
        'eval_with_function': (r'eval\s*\(\s*function', 3),
        'packed_code': (r'eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k', 4),
        'base64_in_js': (r'[A-Za-z0-9+/]{50,}={0,2}', 2),
    }

    # ==================== 反调试模式 ====================
    ANTI_DEBUG_PATTERNS = {
        'debugger_statement': r'debugger\s*[;\n]',
        'console_clear': r'console\.clear\s*\(\s*\)',
        'setInterval_debugger': r'setInterval.*debugger',
        'defineGetter_debugger': r'__defineGetter__.*debugger',
        'devtools_detection': r'devtools.*detection',
        'developer_tools': r'developer.*tools',
        'console_override': r'console\.(log|warn|error|info)\s*=',
        'window_outerHeight': r'window\.outerHeight\s*-\s*window\.innerHeight',
        'firebug_detection': r'firebug',
    }

    # ==================== 自动化检测模式 ====================
    AUTOMATION_DETECTION_PATTERNS = {
        'webdriver': r'navigator\.webdriver',
        'phantom': r'(window\.callPhantom|window\._phantom|phantom)',
        'selenium': r'(selenium|webdriver|__selenium)',
        'puppeteer': r'puppeteer',
        'headless_chrome': r'(headless|HeadlessChrome)',
        'chrome_driver': r'(chromedriver|cdc_)',
        'automation_controlled': r'Automation.*controlled',
    }

    # ==================== 指纹识别模式 ====================
    FINGERPRINTING_PATTERNS = {
        'canvas_fingerprint': r'(canvas\.toDataURL|getImageData)',
        'webgl_fingerprint': r'(WebGLRenderingContext|WEBGL_debug_renderer_info)',
        'audio_fingerprint': r'(AudioContext|OfflineAudioContext|createOscillator)',
        'font_fingerprint': r'(measureText|font.*detect)',
        'screen_fingerprint': r'(screen\.width|screen\.height|screen\.colorDepth)',
        'timezone_fingerprint': r'(getTimezoneOffset|Intl\.DateTimeFormat)',
        'plugin_fingerprint': r'(navigator\.plugins|navigator\.mimeTypes)',
        'battery_fingerprint': r'(navigator\.getBattery|BatteryManager)',
    }

    # ==================== 行为追踪模式 ====================
    BEHAVIOR_TRACKING_PATTERNS = {
        'mouse_tracking': r'(mousemove|mousedown|mouseup|mouseenter|mouseleave)',
        'keyboard_tracking': r'(keydown|keyup|keypress)',
        'scroll_tracking': r'(scroll|wheel)',
        'touch_tracking': r'(touchstart|touchend|touchmove)',
        'focus_tracking': r'(focus|blur|visibilitychange)',
        'clipboard_tracking': r'(copy|paste|cut)',
    }

    # ==================== 内容混淆模式 ====================
    CONTENT_OBFUSCATION_PATTERNS = {
        'base64_data': r'data:[^;]+;base64,',
        'unicode_escape': r'\\u[0-9a-fA-F]{4}',
        'html_entities': r'&#x?[0-9a-fA-F]+;',
        'zero_width_chars': r'[\u200b\u200c\u200d\ufeff]',
        'invisible_text': r'color:\s*transparent|font-size:\s*0',
    }

    # ==================== 加载欺骗模式 ====================
    LOADING_DECEPTION_PATTERNS = {
        'loading_text': r'(loading\.{2,}|please\s+wait|稍等|正在加载)',
        'progress_bar': r'(progress|进度)',
        'spinner': r'(spinner|loader|loading-icon)',
        'percentage': r'\d+%',
    }

    # ==================== 隐藏元素模式 ====================
    HIDDEN_ELEMENT_PATTERNS = {
        'display_none': r'display\s*:\s*none',
        'visibility_hidden': r'visibility\s*:\s*hidden',
        'opacity_zero': r'opacity\s*:\s*0[^.]',
        'position_offscreen': r'(left|top)\s*:\s*-\d{4,}px',
        'height_zero': r'height\s*:\s*0[^.]',
        'width_zero': r'width\s*:\s*0[^.]',
        'clip_hidden': r'clip\s*:\s*rect\(0',
        'overflow_hidden': r'overflow\s*:\s*hidden',
    }

    # ==================== 动态内容模式 ====================
    DYNAMIC_CONTENT_PATTERNS = {
        'dynamic_script': r'createElement\s*\(\s*[\'"]script[\'"]\s*\)',
        'dynamic_iframe': r'createElement\s*\(\s*[\'"]iframe[\'"]\s*\)',
        'innerhtml_script': r'innerHTML\s*=.*<script',
        'document_write_script': r'document\.write\s*\(.*<script',
        'ajax_load': r'(XMLHttpRequest|fetch\s*\()',
    }

    # ==================== 右键菜单阻止模式 ====================
    CONTEXT_MENU_PATTERNS = {
        'contextmenu_prevent': r'(oncontextmenu\s*=|\.oncontextmenu|contextmenu.*preventDefault)',
        'selectstart_prevent': r'(onselectstart\s*=|selectstart.*preventDefault)',
        'dragstart_prevent': r'(ondragstart\s*=|dragstart.*preventDefault)',
        'copy_prevent': r'(oncopy\s*=|copy.*preventDefault)',
    }

    # ==================== VM 检测模式 ====================
    VM_DETECTION_PATTERNS = {
        'vmware': r'vmware',
        'virtualbox': r'virtualbox',
        'qemu': r'qemu',
        'parallels': r'parallels',
        'hyper_v': r'hyper-v',
        'sandbox': r'sandbox',
        'virtual': r'virtual\s*(machine|box|pc)',
    }

    # ==================== 钓鱼内容模式 ====================
    PHISHING_CONTENT_PATTERNS = {
        'urgency_en': r'(urgent|immediate|expire|suspend|limit|within\s+\d+\s+hours)',
        'urgency_cn': r'(紧急|立即|过期|冻结|限制|小时内)',
        'verify_en': r'(verify|confirm|update|secure|validate)',
        'verify_cn': r'(验证|确认|更新|安全|核实)',
        'threat_en': r'(suspended|blocked|violation|unauthorized|unusual)',
        'threat_cn': r'(冻结|封禁|违规|异常|可疑)',
        'action_en': r'(click\s+here|login\s+now|update\s+now)',
        'action_cn': r'(点击这里|立即登录|立即更新)',
    }

    # DOM 噪音检测模式
    DOM_NOISE_PATTERNS = {
        # 隐藏元素中的中文噪音词汇
        'hidden_chinese': r'style="[^"]*(?:font-size:\s*0|position:\s*absolute)[^"]*"[^>]*>([一-龥]{2,10})<',
        # 零尺寸元素
        'zero_size_element': r'style="[^"]*(?:width:\s*[0-9]+px|height:\s*[0-9]+px)[^"]*font-size:\s*0',
        # 绝对定位隐藏
        'absolute_hidden': r'style="[^"]*position:\s*absolute[^"]*top:\s*0[^"]*"',
        # 空标签噪音
        'empty_tags': r'<(h[1-6]|div|span|article|section|nav|aside|footer|header|ol|ul|dd|a)\s+style="[^"]*font-size:\s*0[^"]*"[^>]*>[^<]{0,20}</\1>',
    }

    # CSS 隐藏技术模式
    CSS_HIDING_PATTERNS = {
        'font_size_zero': r'font-size:\s*0(?:rem|px|em|%)?',
        'visibility_hidden': r'visibility:\s*hidden',
        'display_none': r'display:\s*none',
        'position_offscreen': r'(?:left|top|right|bottom):\s*-\d{3,}px',
        'opacity_zero': r'opacity:\s*0[^.]',
        'clip_hidden': r'clip:\s*rect\s*\(\s*0',
        'height_zero': r'height:\s*0(?:px|rem|em)?[;\s"]',
        'width_zero': r'width:\s*0(?:px|rem|em)?[;\s"]',
        'overflow_hidden': r'overflow:\s*hidden',
        'text_indent_offscreen': r'text-indent:\s*-\d{3,}',
        'color_transparent': r'color:\s*transparent',
        'z_index_negative': r'z-index:\s*-\d+',
    }

    def __init__(self):
        """初始化检测器"""
        pass

    def analyze_dom_noise(self, html_content: str) -> DOMNoiseResult:
        """
        分析 DOM 噪音注入

        Args:
            html_content: HTML 内容

        Returns:
            DOMNoiseResult: DOM 噪音检测结果
        """
        result = DOMNoiseResult()

        # 1. 统计隐藏元素中的中文词汇
        hidden_chinese_pattern = r'style="[^"]*(?:font-size:\s*0|position:\s*absolute[^"]*top:\s*0)[^"]*"[^>]*>([一-龥]+)<'
        chinese_matches = re.findall(hidden_chinese_pattern, html_content, re.IGNORECASE)
        result.hidden_chinese_words = len(chinese_matches)

        # 2. 统计零尺寸隐藏元素
        zero_size_pattern = r'<[^>]+style="[^"]*font-size:\s*0[^"]*"[^>]*>'
        zero_size_elements = re.findall(zero_size_pattern, html_content, re.IGNORECASE)
        result.hidden_elements = len(zero_size_elements)

        # 3. 统计空噪音标签
        noise_tag_pattern = r'<(h[1-6]|div|span|article|section|nav|aside|footer|header|ol|ul|dd|a|nav)\s+[^>]*style="[^"]*(?:font-size:\s*0|position:\s*absolute)[^"]*"[^>]*>[^<]{1,30}</\1>'
        noise_tags = re.findall(noise_tag_pattern, html_content, re.IGNORECASE)
        result.noise_elements = len(noise_tags)

        # 4. 统计总元素数（粗略估计）
        all_tags = re.findall(r'<[a-zA-Z][^>]*>', html_content)
        result.total_elements = len(all_tags)

        # 5. 计算噪音比例
        if result.total_elements > 0:
            result.noise_ratio = (result.hidden_elements + result.noise_elements) / result.total_elements

        # 6. 识别使用的技术
        if result.hidden_chinese_words > 10:
            result.techniques.append('中文词汇噪音注入')
        if result.hidden_elements > 20:
            result.techniques.append('零尺寸元素隐藏')
        if result.noise_elements > 30:
            result.techniques.append('噪音标签填充')
        if result.noise_ratio > 0.3:
            result.techniques.append('大规模DOM污染')

        # 7. 评分和严重程度
        score = 0
        if result.hidden_chinese_words > 50:
            score += 15
        elif result.hidden_chinese_words > 20:
            score += 10
        elif result.hidden_chinese_words > 5:
            score += 5

        if result.noise_elements > 100:
            score += 15
        elif result.noise_elements > 50:
            score += 10
        elif result.noise_elements > 20:
            score += 5

        if result.noise_ratio > 0.5:
            score += 10
        elif result.noise_ratio > 0.3:
            score += 5

        result.score = min(score, 30)

        # 严重程度
        if score >= 25:
            result.severity = 'severe'
        elif score >= 15:
            result.severity = 'high'
        elif score >= 8:
            result.severity = 'medium'
        elif score >= 3:
            result.severity = 'low'
        else:
            result.severity = 'none'

        return result

    def analyze_css_evasion(self, html_content: str) -> CSSEvasionResult:
        """
        分析 CSS 规避技术

        Args:
            html_content: HTML 内容

        Returns:
            CSSEvasionResult: CSS 规避检测结果
        """
        result = CSSEvasionResult()

        # 检测各类 CSS 隐藏技术
        result.font_size_zero = len(re.findall(
            self.CSS_HIDING_PATTERNS['font_size_zero'], html_content, re.IGNORECASE))
        result.visibility_hidden = len(re.findall(
            self.CSS_HIDING_PATTERNS['visibility_hidden'], html_content, re.IGNORECASE))
        result.display_none = len(re.findall(
            self.CSS_HIDING_PATTERNS['display_none'], html_content, re.IGNORECASE))
        result.position_offscreen = len(re.findall(
            self.CSS_HIDING_PATTERNS['position_offscreen'], html_content, re.IGNORECASE))
        result.opacity_zero = len(re.findall(
            self.CSS_HIDING_PATTERNS['opacity_zero'], html_content, re.IGNORECASE))
        result.clip_hidden = len(re.findall(
            self.CSS_HIDING_PATTERNS['clip_hidden'], html_content, re.IGNORECASE))

        # 计算总隐藏元素数
        result.total_hidden = (result.font_size_zero + result.visibility_hidden +
                               result.display_none + result.position_offscreen +
                               result.opacity_zero + result.clip_hidden)

        # 评分
        score = 0

        # font-size:0 是最常用的噪音注入技术
        if result.font_size_zero > 100:
            score += 20
        elif result.font_size_zero > 50:
            score += 15
        elif result.font_size_zero > 20:
            score += 10
        elif result.font_size_zero > 5:
            score += 5

        # 其他隐藏技术
        if result.position_offscreen > 10:
            score += 5
        if result.visibility_hidden > 10:
            score += 3
        if result.opacity_zero > 10:
            score += 3

        result.score = min(score, 30)

        # 严重程度
        if score >= 20:
            result.severity = 'severe'
        elif score >= 12:
            result.severity = 'high'
        elif score >= 6:
            result.severity = 'medium'
        elif score >= 2:
            result.severity = 'low'
        else:
            result.severity = 'none'

        return result

    def analyze_html(self, html_content: str) -> EvasionDetectionResult:
        """
        分析 HTML 内容中的规避技术

        Args:
            html_content: HTML 内容字符串

        Returns:
            EvasionDetectionResult: 检测结果
        """
        result = EvasionDetectionResult()
        result.details = {
            'javascript': {},
            'obfuscation': {},
            'anti_debug': {},
            'automation_detection': {},
            'fingerprinting': {},
            'behavior_tracking': {},
            'content_obfuscation': {},
            'loading_deception': {},
            'hidden_elements': {},
            'dynamic_content': {},
            'context_menu': {},
            'vm_detection': {},
            'phishing_content': {},
        }

        score = 0

        # 1. JavaScript 可疑模式检测
        js_result = self._detect_patterns(
            html_content,
            self.JS_SUSPICIOUS_PATTERNS,
            'JavaScript 可疑模式'
        )
        result.details['javascript'] = js_result
        if js_result['detected']:
            score += len(js_result['matches']) * 2
            for pattern in js_result['matches']:
                result.detected_techniques.append(f'JS_{pattern}')
                result.risk_indicators.append(f'suspicious_js_{pattern}')

        # 2. JavaScript 混淆检测
        obf_result = self._detect_obfuscation(html_content)
        result.details['obfuscation'] = obf_result
        if obf_result['has_obfuscation']:
            score += obf_result['score']
            result.detected_techniques.append('JavaScript_Obfuscation')
            result.risk_indicators.append('obfuscated_javascript')

        # 3. 反调试检测
        anti_debug_result = self._detect_patterns(
            html_content,
            self.ANTI_DEBUG_PATTERNS,
            '反调试技术'
        )
        result.details['anti_debug'] = anti_debug_result
        if anti_debug_result['detected']:
            score += len(anti_debug_result['matches']) * 3
            result.detected_techniques.append('Anti_Debug')
            result.risk_indicators.append('anti_debugging')

        # 4. 自动化检测
        automation_result = self._detect_patterns(
            html_content,
            self.AUTOMATION_DETECTION_PATTERNS,
            '自动化检测'
        )
        result.details['automation_detection'] = automation_result
        if automation_result['detected']:
            score += len(automation_result['matches']) * 4
            result.detected_techniques.append('Automation_Detection')
            result.risk_indicators.append('automation_detection')

        # 5. 指纹识别检测
        fp_result = self._detect_patterns(
            html_content,
            self.FINGERPRINTING_PATTERNS,
            '浏览器指纹识别'
        )
        result.details['fingerprinting'] = fp_result
        if fp_result['detected']:
            score += len(fp_result['matches']) * 2
            result.detected_techniques.append('Browser_Fingerprinting')
            result.risk_indicators.append('device_fingerprinting')

        # 6. 行为追踪检测
        behavior_result = self._detect_patterns(
            html_content,
            self.BEHAVIOR_TRACKING_PATTERNS,
            '行为追踪'
        )
        result.details['behavior_tracking'] = behavior_result
        if behavior_result['detected']:
            # 行为追踪需要多个事件同时存在才更可疑
            if len(behavior_result['matches']) >= 3:
                score += 3
                result.detected_techniques.append('Behavior_Tracking')
                result.risk_indicators.append('user_behavior_analysis')

        # 7. 内容混淆检测
        content_obf_result = self._detect_patterns(
            html_content,
            self.CONTENT_OBFUSCATION_PATTERNS,
            '内容混淆'
        )
        result.details['content_obfuscation'] = content_obf_result
        if content_obf_result['detected']:
            score += len(content_obf_result['matches'])
            result.detected_techniques.append('Content_Obfuscation')
            result.risk_indicators.append('obfuscated_content')

        # 8. 加载欺骗检测
        loading_result = self._detect_patterns(
            html_content,
            self.LOADING_DECEPTION_PATTERNS,
            '加载欺骗'
        )
        result.details['loading_deception'] = loading_result
        if loading_result['detected']:
            score += 2
            result.detected_techniques.append('Loading_Deception')
            result.risk_indicators.append('fake_loading')

        # 9. 隐藏元素检测
        hidden_result = self._detect_patterns(
            html_content,
            self.HIDDEN_ELEMENT_PATTERNS,
            '隐藏元素'
        )
        result.details['hidden_elements'] = hidden_result
        if hidden_result['detected']:
            # 隐藏元素需要多个才更可疑
            if len(hidden_result['matches']) >= 3:
                score += 2
                result.detected_techniques.append('Hidden_Elements')
                result.risk_indicators.append('content_concealment')

        # 10. 动态内容检测
        dynamic_result = self._detect_patterns(
            html_content,
            self.DYNAMIC_CONTENT_PATTERNS,
            '动态内容'
        )
        result.details['dynamic_content'] = dynamic_result
        if dynamic_result['detected']:
            score += len(dynamic_result['matches']) * 2
            result.detected_techniques.append('Dynamic_Content_Injection')
            result.risk_indicators.append('dynamic_code_loading')

        # 11. 右键菜单阻止检测
        context_result = self._detect_patterns(
            html_content,
            self.CONTEXT_MENU_PATTERNS,
            '右键菜单阻止'
        )
        result.details['context_menu'] = context_result
        if context_result['detected']:
            score += 2
            result.detected_techniques.append('Context_Menu_Block')
            result.risk_indicators.append('user_interaction_blocking')

        # 12. VM 检测
        vm_result = self._detect_patterns(
            html_content,
            self.VM_DETECTION_PATTERNS,
            'VM检测'
        )
        result.details['vm_detection'] = vm_result
        if vm_result['detected']:
            score += len(vm_result['matches']) * 3
            result.detected_techniques.append('VM_Detection')
            result.risk_indicators.append('sandbox_evasion')

        # 13. 钓鱼内容检测
        phishing_result = self._detect_patterns(
            html_content,
            self.PHISHING_CONTENT_PATTERNS,
            '钓鱼内容'
        )
        result.details['phishing_content'] = phishing_result
        if phishing_result['detected']:
            score += len(phishing_result['matches'])
            result.detected_techniques.append('Phishing_Content')
            result.risk_indicators.append('psychological_manipulation')

        # 14. DOM 噪音分析
        dom_noise_result = self.analyze_dom_noise(html_content)
        result.dom_noise = dom_noise_result
        result.details['dom_noise'] = {
            'detected': dom_noise_result.severity != 'none',
            'severity': dom_noise_result.severity,
            'hidden_elements': dom_noise_result.hidden_elements,
            'noise_elements': dom_noise_result.noise_elements,
            'hidden_chinese_words': dom_noise_result.hidden_chinese_words,
            'noise_ratio': dom_noise_result.noise_ratio,
            'techniques': dom_noise_result.techniques,
        }
        if dom_noise_result.severity in ('high', 'severe'):
            score += dom_noise_result.score
            result.detected_techniques.append('DOM_Noise_Injection')
            result.risk_indicators.append('dom_noise_pollution')
        elif dom_noise_result.severity == 'medium':
            score += dom_noise_result.score // 2
            result.detected_techniques.append('DOM_Noise_Injection')

        # 15. CSS 规避分析
        css_evasion_result = self.analyze_css_evasion(html_content)
        result.css_evasion = css_evasion_result
        result.details['css_evasion'] = {
            'detected': css_evasion_result.severity != 'none',
            'severity': css_evasion_result.severity,
            'font_size_zero': css_evasion_result.font_size_zero,
            'visibility_hidden': css_evasion_result.visibility_hidden,
            'display_none': css_evasion_result.display_none,
            'position_offscreen': css_evasion_result.position_offscreen,
            'total_hidden': css_evasion_result.total_hidden,
        }
        if css_evasion_result.severity in ('high', 'severe'):
            score += css_evasion_result.score
            result.detected_techniques.append('CSS_Content_Hiding')
            result.risk_indicators.append('css_content_concealment')
        elif css_evasion_result.severity == 'medium':
            score += css_evasion_result.score // 2
            result.detected_techniques.append('CSS_Content_Hiding')

        # 计算总结
        result.total_techniques = len(result.detected_techniques)
        result.anti_detection_score = min(score, 100)  # 提高上限到100

        # 确定复杂度（调整阈值）
        if score >= 40:
            result.evasion_complexity = 'very_high'
        elif score >= 25:
            result.evasion_complexity = 'high'
        elif score >= 12:
            result.evasion_complexity = 'medium'
        elif score >= 5:
            result.evasion_complexity = 'low'
        else:
            result.evasion_complexity = 'minimal'

        return result

    def _detect_patterns(self, content: str, patterns: Dict[str, str],
                         category: str) -> Dict[str, Any]:
        """
        检测一组模式

        Args:
            content: 要检测的内容
            patterns: 模式字典 {名称: 正则表达式}
            category: 类别名称

        Returns:
            检测结果字典
        """
        result = {
            'category': category,
            'detected': False,
            'matches': [],
            'match_details': {}
        }

        for name, pattern in patterns.items():
            try:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                if matches:
                    result['detected'] = True
                    result['matches'].append(name)
                    result['match_details'][name] = {
                        'count': len(matches),
                        'samples': matches[:3]  # 最多保留3个样本
                    }
            except re.error:
                continue

        return result

    def _detect_obfuscation(self, content: str) -> Dict[str, Any]:
        """
        检测 JavaScript 混淆

        Args:
            content: JavaScript 内容

        Returns:
            混淆检测结果
        """
        result = {
            'has_obfuscation': False,
            'score': 0,
            'indicators': [],
            'details': {}
        }

        score = 0

        for name, (pattern, weight) in self.JS_OBFUSCATION_PATTERNS.items():
            try:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                if matches:
                    result['indicators'].append(name)
                    result['details'][name] = {
                        'count': len(matches),
                        'weight': weight
                    }
                    score += weight
            except re.error:
                continue

        result['score'] = min(score, 10)  # 最高10分
        result['has_obfuscation'] = score >= 3

        return result

    def get_technique_description(self, technique: str) -> str:
        """
        获取技术的中文描述

        Args:
            technique: 技术名称

        Returns:
            中文描述
        """
        descriptions = {
            'JS_eval': 'JavaScript eval() 动态代码执行',
            'JS_document_write': 'document.write() 动态内容注入',
            'JS_fromCharCode': 'String.fromCharCode() 字符编码',
            'JS_atob': 'Base64 解码执行',
            'JS_debugger': '调试器断点陷阱',
            'JavaScript_Obfuscation': 'JavaScript 代码混淆',
            'Anti_Debug': '反调试技术',
            'Automation_Detection': '自动化/爬虫检测',
            'Browser_Fingerprinting': '浏览器指纹识别',
            'Behavior_Tracking': '用户行为追踪',
            'Content_Obfuscation': '内容混淆隐藏',
            'Loading_Deception': '虚假加载欺骗',
            'Hidden_Elements': '隐藏元素',
            'Dynamic_Content_Injection': '动态内容注入',
            'Context_Menu_Block': '右键菜单阻止',
            'VM_Detection': '虚拟机/沙箱检测',
            'Phishing_Content': '钓鱼话术',
            'DOM_Noise_Injection': 'DOM 噪音注入',
            'CSS_Content_Hiding': 'CSS 内容隐藏',
        }
        return descriptions.get(technique, technique)

    def get_risk_description(self, indicator: str) -> str:
        """
        获取风险指标的中文描述

        Args:
            indicator: 风险指标

        Returns:
            中文描述
        """
        descriptions = {
            'suspicious_js_eval': '使用 eval() 可执行任意代码',
            'obfuscated_javascript': 'JavaScript 代码经过混淆处理',
            'anti_debugging': '存在反调试机制阻止分析',
            'automation_detection': '检测自动化工具以规避爬虫',
            'device_fingerprinting': '收集设备指纹用于追踪',
            'user_behavior_analysis': '分析用户行为模式',
            'obfuscated_content': '内容经过混淆处理',
            'fake_loading': '使用虚假加载页面延迟显示',
            'content_concealment': '隐藏可疑内容',
            'dynamic_code_loading': '动态加载代码规避检测',
            'user_interaction_blocking': '阻止用户交互操作',
            'sandbox_evasion': '检测沙箱环境以规避分析',
            'psychological_manipulation': '使用紧迫性话术施压',
            'dom_noise_pollution': '大量 DOM 噪音干扰内容分析',
            'css_content_concealment': '使用 CSS 技术隐藏内容',
        }
        return descriptions.get(indicator, indicator)


def format_evasion_report(result: EvasionDetectionResult,
                          verbose: bool = False) -> str:
    """
    格式化规避技术检测报告

    Args:
        result: 检测结果
        verbose: 是否显示详细信息

    Returns:
        格式化的报告字符串
    """
    detector = EvasionPatternDetector()

    lines = []
    lines.append("=" * 60)
    lines.append("规避技术检测报告 (基于 CloakHunter)")
    lines.append("=" * 60)
    lines.append("")

    # 总体评估
    complexity_display = {
        'minimal': '[+] 极低',
        'low': '[+] 低',
        'medium': '[*] 中等',
        'high': '[!] 较高',
        'very_high': '[!] 很高',
    }

    lines.append("【规避复杂度】")
    lines.append(f"  等级: {complexity_display.get(result.evasion_complexity, result.evasion_complexity)}")
    lines.append(f"  评分: {result.anti_detection_score}/30")
    lines.append(f"  检测到技术数: {result.total_techniques}")
    lines.append("")

    # 检测到的技术
    if result.detected_techniques:
        lines.append("【检测到的规避技术】")
        for tech in result.detected_techniques:
            desc = detector.get_technique_description(tech)
            lines.append(f"  - {desc}")
        lines.append("")

    # 风险指标
    if result.risk_indicators:
        lines.append("【风险指标】")
        for indicator in result.risk_indicators:
            desc = detector.get_risk_description(indicator)
            lines.append(f"  - {desc}")
        lines.append("")

    # 详细信息（可选）
    if verbose and result.details:
        lines.append("【详细检测结果】")
        for category, data in result.details.items():
            if isinstance(data, dict) and data.get('detected'):
                lines.append(f"  [{category}]")
                for match in data.get('matches', []):
                    detail = data.get('match_details', {}).get(match, {})
                    count = detail.get('count', 0)
                    lines.append(f"    - {match}: {count} 处")
        lines.append("")

    lines.append("=" * 60)

    return '\n'.join(lines)


if __name__ == '__main__':
    import argparse
    import sys

    parser = argparse.ArgumentParser(description='URL 规避技术检测工具')
    parser.add_argument('file', nargs='?', help='HTML 文件路径')
    parser.add_argument('-v', '--verbose', action='store_true', help='显示详细信息')
    parser.add_argument('--json', action='store_true', help='JSON 格式输出')

    args = parser.parse_args()

    if not args.file:
        # 演示模式
        demo_html = """
        <html>
        <script>
            eval(atob('YWxlcnQoJ3Rlc3QnKQ=='));
            navigator.webdriver;
            canvas.toDataURL();
            document.oncontextmenu = function() { return false; };
        </script>
        <div style="display:none">Hidden content</div>
        <p>Your account will be suspended! Verify immediately!</p>
        </html>
        """
        detector = EvasionPatternDetector()
        result = detector.analyze_html(demo_html)
        print(format_evasion_report(result, verbose=True))
    else:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                html_content = f.read()

            detector = EvasionPatternDetector()
            result = detector.analyze_html(html_content)

            if args.json:
                import json
                output = {
                    'total_techniques': result.total_techniques,
                    'detected_techniques': result.detected_techniques,
                    'risk_indicators': result.risk_indicators,
                    'anti_detection_score': result.anti_detection_score,
                    'evasion_complexity': result.evasion_complexity,
                    'details': result.details,
                }
                print(json.dumps(output, ensure_ascii=False, indent=2))
            else:
                print(format_evasion_report(result, verbose=args.verbose))

            # 根据复杂度返回退出码
            if result.evasion_complexity in ('very_high', 'high'):
                sys.exit(2)
            elif result.evasion_complexity == 'medium':
                sys.exit(1)

        except FileNotFoundError:
            print(f"错误: 文件不存在 - {args.file}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"错误: {e}", file=sys.stderr)
            sys.exit(1)
