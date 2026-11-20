"""标准字段目录：领域资产的确定性加载、解析与查找。

单一事实源是技能目录 ``assets/`` 三件（标准字段.txt / field_synonyms.json /
tag_rules.json），只读加载。标准名解析（normalize/compact/中文系统名/中文别
名四路索引）、映射目标黑名单、枚举字段短路都必须经过本模块，禁止在别处复制
索引或校验逻辑。

资产定位：随技能目录自包含——本模块上一级的 ``<parser-skills>/assets/``
（技能目录被单独拷贝分发时同样可达；``resolve()`` 兼容 Junction / 符号链接
部署）；也可用 ``load_catalog(assets_dir=...)`` 显式指定。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence


STANDARD_FIELD_COLUMNS = (
    "系统属性名称",
    "属性分类",
    "字段名称",
    "属性类型",
    "描述",
    "枚举值",
    "对象",
)

#: 映射目标黑名单：这些标准字段只能由各自的专属链路写入（事件名称/事件级别由
#: 事件标注链路持有，日志类型由日志分类链路持有，威胁类型由威胁链路持有），
#: 字段映射收口命中即降级「未匹配」。成员本身在目录内合法，目录解析通过不代
#: 表允许映射——收口必须显式查本表。
MAPPING_EXCLUDED_STANDARD_FIELDS = frozenset(
    {"事件名称", "事件级别", "日志类型", "威胁类型"}
)

#: 输入侧排除索引：这些 normalize[].index 不参与字段映射（original_log 为审计
#: 锚点、日志类型由分类链路写入、事件名称/事件级别由事件标注链路写入）。与
#: MAPPING_EXCLUDED_STANDARD_FIELDS（目标侧）成对，方向不同、成员不同。
MAPPING_EXCLUDED_INDICES = frozenset(
    {"original_log", "日志类型", "事件名称", "事件级别"}
)

_ASSETS_DIR = Path(__file__).resolve().parents[1] / "assets"
_STANDARD_FIELDS_NAME = "标准字段.txt"
_SYNONYMS_NAME = "field_synonyms.json"
_TAG_RULES_NAME = "tag_rules.json"


def default_assets_dir() -> Path:
    """返回领域资产目录（技能目录 ``assets/``）。"""
    return _ASSETS_DIR


def normalize_field_name(name: str) -> str:
    """把 snake / kebab / camel 书写的字段名归一为一个查找键。"""
    normalized = name.replace("-", "_")
    normalized = re.sub(r"([a-z])([A-Z])", r"\1_\2", normalized)
    normalized = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", normalized)
    return normalized.lower()


def compact_field_name(name: str) -> str:
    """返回去掉分隔符的次级查找键。"""
    return re.sub(r"[_\-\s]", "", name).lower()


@dataclass(frozen=True, slots=True)
class StandardField:
    """标准字段表中的一行（不可变）。"""

    system_property_name: str
    category: str
    field_name: str
    data_type: str
    description: str
    enum_values: str
    objects: str

    def as_record(self) -> dict[str, str]:
        """按历史列名返回一份可变副本。"""
        return dict(
            zip(
                STANDARD_FIELD_COLUMNS,
                (
                    self.system_property_name,
                    self.category,
                    self.field_name,
                    self.data_type,
                    self.description,
                    self.enum_values,
                    self.objects,
                ),
            )
        )


class StandardFieldCatalog:
    """标准字段目录：不可变行集 + 确定性查找索引。"""

    def __init__(
        self,
        fields: Sequence[StandardField],
        synonyms: Mapping[str, Mapping[str, Any]],
        tag_rules: Mapping[str, Sequence[str]],
    ) -> None:
        self._fields = tuple(fields)
        self._synonyms = _freeze_synonyms(synonyms)
        self._tag_rules = MappingProxyType(
            {name: tuple(keywords) for name, keywords in tag_rules.items()}
        )
        self._name_index = MappingProxyType(
            self.build_name_index(field.as_record() for field in self._fields)
        )

    @classmethod
    def from_resources(
        cls,
        standard_fields_path: Path,
        synonyms_path: Path,
        tag_rules_path: Path,
    ) -> "StandardFieldCatalog":
        """解析三份资产文件。标准字段表缺失或表头不符立即抛错。"""
        standard_fields_text = Path(standard_fields_path).read_text(encoding="utf-8")
        fields = _parse_standard_fields(standard_fields_text)
        synonyms = _read_json_mapping(synonyms_path)
        tag_resource = _read_json_mapping(tag_rules_path)
        raw_rules = tag_resource.get("rules", tag_resource)
        tag_rules = raw_rules if isinstance(raw_rules, Mapping) else {}
        return cls(fields, synonyms, tag_rules)

    @property
    def fields(self) -> tuple[StandardField, ...]:
        return self._fields

    @property
    def synonyms(self) -> Mapping[str, Mapping[str, Any]]:
        return self._synonyms

    @property
    def tag_rules(self) -> Mapping[str, tuple[str, ...]]:
        return self._tag_rules

    @property
    def name_index(self) -> Mapping[str, int]:
        return self._name_index

    def records(self) -> list[dict[str, str]]:
        """返回防御性可变副本列表。"""
        return [field.as_record() for field in self._fields]

    def lookup(self, name: str) -> StandardField | None:
        """按原名 / 规范化名 / 紧凑名查找；未命中返回 None。"""
        for key in _lookup_keys(name):
            index = self._name_index.get(key)
            if index is not None:
                return self._fields[index]
        return None

    def build_name_index(
        self, records: Iterable[Mapping[str, Any]]
    ) -> dict[str, int]:
        """按记录顺序构建 first-wins 查找索引。"""
        index: dict[str, int] = {}
        field_name_to_index: dict[str, int] = {}
        for position, record in enumerate(records):
            field_name = str(record.get("字段名称", ""))
            if not field_name:
                continue
            for key in (
                normalize_field_name(field_name),
                compact_field_name(field_name),
            ):
                index.setdefault(key, position)
            field_name_to_index.setdefault(field_name.lower(), position)
            system_name = str(record.get("系统属性名称", ""))
            if system_name:
                index.setdefault(system_name, position)

        for synonym_key, entry in self._synonyms.items():
            target = field_name_to_index.get(synonym_key.lower())
            if target is None:
                continue
            for alias in entry.get("zh", ()):
                if not alias:
                    continue
                index.setdefault(str(alias), target)
        return index


def load_catalog(assets_dir: Path | str | None = None) -> StandardFieldCatalog:
    """从资产目录加载目录实例（无进程级全局状态，调用方自持）。"""
    directory = Path(assets_dir) if assets_dir is not None else default_assets_dir()
    return StandardFieldCatalog.from_resources(
        directory / _STANDARD_FIELDS_NAME,
        directory / _SYNONYMS_NAME,
        directory / _TAG_RULES_NAME,
    )


# ---------------------------------------------------------------------------
# 枚举字段确定性短路
# ---------------------------------------------------------------------------

#: 参与确定性短路的枚举目标字段 → 外层 value 默认值。白名单唯一来源仍是标准
#: 字段表的「枚举值」列；本表不复制枚举集合。
ENUM_AUTO_MAPPING_TARGETS: Mapping[str, str] = MappingProxyType({
    "HTTP请求方法": "其他",
    "操作系统平台": "others",
    "事件状态": "未知",
    "事件结果": "未知",
    "威胁等级": "提醒",
    "攻击结果": "未知",
    "登录系统": "未知",
    "事件动作": "未知",
})

#: 显式排除的标准字段：操作类型由事件标注链路持有，威胁类型走独立链路。
ENUM_AUTO_MAPPING_EXCLUSIONS: tuple[str, ...] = ("操作类型", "威胁类型")


@dataclass(frozen=True, slots=True)
class EnumMappingPolicy:
    """一个枚举目标字段的短路策略。"""

    system_property_name: str
    field_name: str
    default_value: str
    whitelist: tuple[str, ...]


def enum_auto_mapping_policies(catalog: StandardFieldCatalog) -> dict[str, EnumMappingPolicy]:
    """从目录事实解析枚举目标策略；资产漂移（行缺失/类型不符/默认值越界）立即失败。"""
    overlap = set(ENUM_AUTO_MAPPING_EXCLUSIONS) & set(ENUM_AUTO_MAPPING_TARGETS)
    if overlap:
        raise ValueError(f"枚举短路排除字段与目标重叠: {sorted(overlap)}")
    policies: dict[str, EnumMappingPolicy] = {}
    for system_name, default_value in ENUM_AUTO_MAPPING_TARGETS.items():
        field = next(
            (item for item in catalog.fields if item.system_property_name == system_name),
            None,
        )
        if field is None:
            raise ValueError(f"枚举短路目标字段不存在: {system_name}")
        if field.data_type != "枚举":
            raise ValueError(
                f"枚举短路目标 {system_name} 属性类型为 {field.data_type!r}，应为「枚举」"
            )
        whitelist = tuple(
            value.strip() for value in field.enum_values.split(",") if value.strip()
        )
        if not whitelist:
            raise ValueError(f"枚举短路目标 {system_name} 白名单为空")
        if default_value not in whitelist:
            raise ValueError(
                f"枚举短路目标 {system_name} 默认值 {default_value!r} 不在白名单内"
            )
        policies[system_name] = EnumMappingPolicy(
            system_property_name=system_name,
            field_name=field.field_name,
            default_value=default_value,
            whitelist=whitelist,
        )
    return policies


def resolve_enum_field(
    raw_field_name: str, catalog: StandardFieldCatalog
) -> tuple[str, str] | None:
    """确定性解析原始字段名是否命中枚举短路目标之一。

    返回 ``(系统属性名称, 来源)``，来源为 ``exact``（规范化名/紧凑名与目标英
    文字段名一致）或 ``synonym``（目录中文别名或同义词表桥接命中）；未命中目标
    （含命中其他标准字段）返回 None，该字段继续走候选检索主路径。
    """
    policies = enum_auto_mapping_policies(catalog)
    record = catalog.lookup(raw_field_name)
    if record is not None and record.system_property_name in policies:
        if (
            normalize_field_name(raw_field_name) == normalize_field_name(record.field_name)
            or compact_field_name(raw_field_name) == compact_field_name(record.field_name)
        ):
            return record.system_property_name, "exact"
        return record.system_property_name, "synonym"

    normalized = normalize_field_name(raw_field_name)
    compact = compact_field_name(raw_field_name)
    for synonym_key, entry in catalog.synonyms.items():
        target = next(
            (
                policy
                for policy in policies.values()
                if policy.field_name == str(entry.get("en", ""))
            ),
            None,
        )
        if target is None:
            continue
        key_normalized = normalize_field_name(str(synonym_key))
        if normalized == key_normalized or compact == compact_field_name(str(synonym_key)):
            return target.system_property_name, "synonym"
    return None


def _parse_standard_fields(raw: str) -> tuple[StandardField, ...]:
    lines = [line.strip() for line in raw.strip().splitlines() if line.strip()]
    if not lines:
        return ()
    header = tuple(column.strip() for column in lines[0].split("\t"))
    if header:
        header = (header[0].lstrip("\ufeff"), *header[1:])
    if header != STANDARD_FIELD_COLUMNS:
        raise ValueError(f"Unexpected standard-field schema: {header!r}")

    fields: list[StandardField] = []
    for line in lines[1:]:
        columns = [column.strip() for column in line.split("\t")]
        columns.extend([""] * (len(STANDARD_FIELD_COLUMNS) - len(columns)))
        fields.append(StandardField(*columns[: len(STANDARD_FIELD_COLUMNS)]))
    return tuple(fields)


def _lookup_keys(name: str) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys((name, normalize_field_name(name), compact_field_name(name)))
    )


def _read_json_mapping(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    return value if isinstance(value, Mapping) else {}


def _freeze_synonyms(
    synonyms: Mapping[str, Mapping[str, Any]],
) -> Mapping[str, Mapping[str, Any]]:
    frozen: dict[str, Mapping[str, Any]] = {}
    for name, entry in synonyms.items():
        if not isinstance(entry, Mapping):
            continue
        frozen[name] = MappingProxyType(
            {
                "en": str(entry.get("en", "")),
                "zh": tuple(str(alias) for alias in entry.get("zh", ())),
            }
        )
    return MappingProxyType(frozen)
