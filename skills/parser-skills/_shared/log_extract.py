"""数据族确定性提取与聚合：JSON / KV 特征值提取、按值聚合、覆盖探针。

纯离线实现（不依赖 LLM API、不依赖外部进程）。log-classification /
field-mapping / enum-mapping 的日志值提取必须经过本模块，禁止复制。

设计取舍（记录在案，出处与迁移对照见 issue tracker #10）：
- 样本保留**原始行**（而非剥头后的日志体）——统计报告的读者是宿主
  agent，完整行信息量更大；
- KV 全键提取状态机支持多字符字段分隔符（如 "||"）。
"""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any, Callable, List, Optional, Tuple

_JSON_BODY_RE = re.compile(r"\{[\S\s]*\}")

# KV 值提取的异常字符清理类别表
_CLEAN_CHAR_CATEGORIES: Tuple[Tuple[str, ...], ...] = (
    ("\ufeff",),
    ("\u200b", "\u200c", "\u200d", "\u200e", "\u200f"),
    tuple(chr(i) for i in range(0x00, 0x20) if i not in (0x09, 0x0A, 0x0D)),
    ("\ufffe", "\uffff", "\u2028", "\u2029", "\u00a0", "\u3000"),
)

# 派生分隔符候选排除的结构/噪声字符
_DERIVED_SEPARATOR_EXCLUDE = set('=: \t"\'`{}[]()<>.-/\\_+')

# 数据裁决：特征键行覆盖率阈值
BODY_KEY_COVERAGE_THRESHOLD = 0.8


# ---------------------------------------------------------------------------
# JSON：嵌套取值与日志头剥离
# ---------------------------------------------------------------------------

def _get_nested_json_value(obj: dict, path: str) -> Any:
    """沿点分隔路径遍历嵌套字典；任意键缺失或中间节点非字典返回 None。"""
    if not path:
        return None
    current: Any = obj
    for key in path.split("."):
        if isinstance(current, dict):
            current = current.get(key)
            if current is None:
                return None
        else:
            return None
    return current


def extract_json_body(line: str) -> Optional[str]:
    """从第一个 { 匹配到最后一个 }（贪婪，跨行）。"""
    match = _JSON_BODY_RE.search(line)
    return match.group(0) if match else None


def strip_header(line: str, header_end_marker: str = "", *, is_json: bool = True) -> str:
    """剥离日志头，返回 body。

    - is_json=True：优先取 {...}（不依赖 marker，避免 syslog 头多空格
      误切断）；行内无大括号时降级按 marker 切分。
    - is_json=False：按 marker 从左切分一次；marker 为空或未命中返回原行。
    """
    if not line:
        return line
    if is_json:
        body = extract_json_body(line)
        if body:
            return body
    if header_end_marker:
        parts = line.split(header_end_marker, 1)
        if len(parts) == 2:
            return parts[1]
    return line


def extract_json_value(line: str, feature_field: str) -> Any:
    """从 JSON 日志行提取字段值（支持纯 JSON 与 syslog 头 + JSON）。

    feature_field 支持点分隔嵌套路径（如 "event.action"）。
    解析或查找失败返回 None。
    """
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        start = line.find("{")
        end = line.rfind("}")
        if start != -1 and end > start:
            try:
                obj = json.loads(line[start:end + 1])
            except (json.JSONDecodeError, ValueError):
                return None
        else:
            return None
    return _get_nested_json_value(obj, feature_field)


# ---------------------------------------------------------------------------
# KV：动态正则值提取
# ---------------------------------------------------------------------------

class KvValueExtractor:
    """从 KV 日志行提取字段值，支持多种字段/键值分隔符组合。

    field_delimit 为字段分隔符（" "、"space"、"\\t" 归一化为空白模式），
    kv_delimit 为键值分隔符（"="、":" 等）。支持引号值（可含空格）与
    异常字符清理。
    """

    def __init__(self, field_delimit: str, kv_delimit: str) -> None:
        self.field_delimit = field_delimit
        self.kv_delimit = kv_delimit

        if field_delimit in (" ", "space", "\t"):
            field_mode = "space"
            field_pattern = r"\s+"
        else:
            field_mode = field_delimit
            field_pattern = re.escape(field_delimit)
        kv_pattern = re.escape(kv_delimit)

        # 键名排除「分隔符字符 + = + 空白」，防止键名贪婪吞掉分隔符；
        # 字符类内只转义真正的元字符，避免 bad escape
        key_exclude_raw = kv_delimit if field_mode == "space" else field_delimit + kv_delimit
        key_exclude_escaped = re.sub(r"([\]\\^\-])", r"\\\1", key_exclude_raw)
        key_class = rf"[^{key_exclude_escaped}=\s]+"

        self._pattern = re.compile(
            rf'(?:^|{field_pattern}\s*)({key_class})\s*{kv_pattern}'
            rf'(?:"([^"\\]*(?:\\.[^"\\]*)*)"|([^{field_pattern}"]+))'
        )

    @staticmethod
    def _clean_special_chars(text: str) -> str:
        """清理 BOM / 零宽 / 控制字符 / 特殊空白。"""
        if not text:
            return text
        cleaned = text
        for chars in _CLEAN_CHAR_CATEGORIES:
            for char in chars:
                if char in cleaned:
                    cleaned = cleaned.replace(char, "")
        return cleaned

    def extract_value(self, line: str, feature_field: str) -> Any:
        """提取指定键的值；键不存在或解析失败返回 None。"""
        if not line or not feature_field:
            return None
        cleaned_line = self._clean_special_chars(line)
        for match in self._pattern.finditer(cleaned_line):
            if match.group(1) == feature_field:
                quoted, unquoted = match.group(2), match.group(3)
                value = quoted if quoted is not None else unquoted
                if value is not None:
                    value = self._clean_special_chars(str(value))
                    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                        value = value[1:-1]
                    value = value.replace("\n", "").replace("\r", "").replace("\t", "")
                return value
        return None


# ---------------------------------------------------------------------------
# 聚合
# ---------------------------------------------------------------------------

_ExtractorFunc = Callable[[str, str], Any]


def aggregate_by_field(
    logs_str: str,
    feature_field: str,
    extractor: _ExtractorFunc,
    sample_limit: int = 3,
    sample_max_chars: int = 300,
) -> dict:
    """按特征字段值对日志行分组：计数、采样、未匹配行统计。

    样本保留原始行（截断到 sample_max_chars），每个值最多
    sample_limit 条；未匹配行不归入任何值，仅保留少量样本。
    返回 aggregation 结构：
    {total_lines, matched_lines, unmatched_lines, unmatched_samples,
     feature_field, values: {value: {count, samples}}, value_count,
     top_values（前 20，按计数降序）}
    """
    lines = [line for line in logs_str.split("\n") if line.strip()]
    total_lines = len(lines)
    matched_lines = 0

    value_counter: Counter = Counter()
    value_samples: dict = {}
    unmatched_samples: List[str] = []

    for line in lines:
        feature_value = extractor(line, feature_field)
        if feature_value is None:
            if len(unmatched_samples) < sample_limit:
                sample = line[:sample_max_chars].strip()
                if sample and sample not in unmatched_samples:
                    unmatched_samples.append(sample)
            continue
        matched_lines += 1
        feature_str = str(feature_value)
        value_counter[feature_str] += 1
        samples = value_samples.setdefault(feature_str, [])
        if len(samples) < sample_limit:
            sample = line[:sample_max_chars].strip()
            if sample not in samples:
                samples.append(sample)

    return {
        "total_lines": total_lines,
        "matched_lines": matched_lines,
        "unmatched_lines": total_lines - matched_lines,
        "unmatched_samples": unmatched_samples,
        "feature_field": feature_field,
        "values": {
            val: {"count": cnt, "samples": value_samples.get(val, [])}
            for val, cnt in value_counter.most_common()
        },
        "value_count": len(value_counter),
        "top_values": [v for v, _ in value_counter.most_common(20)],
    }


# ---------------------------------------------------------------------------
# 数据裁决探针
# ---------------------------------------------------------------------------

def kv_key_line_coverage(
    logs_str: str, feature_field: str, field_delimit: str, kv_delimit: str,
    max_lines: int = 50,
) -> float:
    """全行扫描特征键的行覆盖率（0~1），供确定性分隔符裁决。"""
    probe = KvValueExtractor(field_delimit, kv_delimit)
    lines = [line for line in logs_str.split("\n") if line.strip()][:max_lines]
    if not lines:
        return 0.0
    hits = sum(1 for line in lines if probe.extract_value(line, feature_field) is not None)
    return hits / len(lines)


def derive_separator_candidates(logs_str: str, max_lines: int = 50) -> List[str]:
    """从采样行统计高频结构符号，派生候选字段分隔符（盲发现通道）。

    字段分隔符在多字段行中天然高频（N 个字段出现 N-1 次），只把平均
    每行出现 ≥2 次的符号交给覆盖率探针裁决；错误候选会被
    BODY_KEY_COVERAGE_THRESHOLD 阈值否决。
    """
    lines = [line for line in logs_str.split("\n") if line.strip()][:max_lines]
    if not lines:
        return []
    freq = Counter(
        char
        for line in lines
        for char in line
        if not char.isalnum() and char not in _DERIVED_SEPARATOR_EXCLUDE
    )
    return [char for char, count in freq.most_common(8) if count >= 2 * len(lines)]


# ---------------------------------------------------------------------------
# 引号/括号感知的 KV 全键提取
# ---------------------------------------------------------------------------

_DELIMIT_MAP = {"space": " ", "comma": ",", "semicolon": ";", "tab": "\t"}


def _split_kv_segments(text: str, delimit: str = " ", tab: str = "=") -> List[str]:
    """按字段分隔符拆分 KV 文本为 segment 列表（引号/括号感知）。

    仅在「深度全 0 且不在任何引号内」时分隔符视为字段边界；引号内的
    转义、方括号/花括号嵌套内的分隔符均不切分。支持多字符字段分隔符
    （如 "||"——逐字符比较的实现会漏切多字符分隔符）。
    """
    actual_delimit = _DELIMIT_MAP.get(delimit.lower(), delimit)
    is_space_delimit = actual_delimit == " "
    delim_len = len(actual_delimit)

    segments: List[str] = []
    current: List[str] = []
    in_double_quote = False
    in_single_quote = False
    bracket_depth = 0
    brace_depth = 0
    prev_escape = False

    i = 0
    total = len(text)
    while i < total:
        ch = text[i]
        if prev_escape:
            current.append(ch)
            prev_escape = False
            i += 1
            continue
        if ch == "\\" and (in_double_quote or in_single_quote):
            current.append(ch)
            prev_escape = True
            i += 1
            continue
        if ch == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
            current.append(ch)
            i += 1
            continue
        if ch == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
            current.append(ch)
            i += 1
            continue
        if not in_double_quote and not in_single_quote:
            if ch == "[":
                bracket_depth += 1
            elif ch == "]":
                bracket_depth = max(0, bracket_depth - 1)
            elif ch == "{":
                brace_depth += 1
            elif ch == "}":
                brace_depth = max(0, brace_depth - 1)
        at_depth_zero = (
            bracket_depth == 0 and brace_depth == 0
            and not in_double_quote and not in_single_quote
        )
        if at_depth_zero and (
            (is_space_delimit and ch.isspace())
            or (not is_space_delimit and text.startswith(actual_delimit, i))
        ):
            segments.append("".join(current))
            current = []
            i += delim_len if not is_space_delimit else 1
            continue
        current.append(ch)
        i += 1

    if current:
        segments.append("".join(current))
    return segments


def extract_kv_pairs(
    text: str, delimit: str = " ", tab: str = "=",
) -> List[Tuple[str, str]]:
    """从 KV 文本提取全部 (key, value) 对（保留重复，供值画像计数）。

    segment 内第一个 tab 之前为 key（去首尾空白），之后为值原样保留；
    无 tab 的 segment 跳过。
    """
    pairs: List[Tuple[str, str]] = []
    for segment in _split_kv_segments(text, delimit, tab):
        stripped = segment.strip()
        if not stripped:
            continue
        index = stripped.find(tab)
        if index > 0:
            key = stripped[:index].strip()
            if key:
                pairs.append((key, stripped[index + len(tab):]))
    return pairs


def extract_kv_keys(text: str, delimit: str = " ", tab: str = "=") -> List[str]:
    """从 KV 文本提取去重后的字段名列表（保持首次出现顺序）。"""
    keys: List[str] = []
    seen = set()
    for key, _value in extract_kv_pairs(text, delimit, tab):
        if key not in seen:
            seen.add(key)
            keys.append(key)
    return keys
