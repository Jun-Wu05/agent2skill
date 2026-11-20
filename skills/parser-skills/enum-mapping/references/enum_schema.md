# enum-mapping JSON 契约

四个契约 + stdout 摘要的字段说明。脚本对缺失可选字段的容忍度：映射对的 `mappingType` 缺省视为 EQUAL、`mappingValue` 缺省回退 orgValue；其余输入字段由脚本严格校验。

## 1. enum_values.json（提取产物，归类输入）

```json
{
  "field": "event_type",
  "log_format": "kv",
  "format_context": {"field_delimit": " ", "kv_delimit": "="},
  "header_end_marker": "app[1]: ",
  "total_lines": 1206,
  "matched_lines": 1190,
  "unmatched_lines": 16,
  "unmatched_samples": ["<首条未命中样本，≤3 条，截断 300 字符>"],
  "unique_count": 8,
  "values": ["login", "logout"],
  "value_counts": {"login": 900, "logout": 290},
  "original_log": {"login": "<该值首条原始日志样本>"},
  "max_values": 100,
  "truncated": false,
  "input": "logs.xlsx",
  "sheet": "数据表"
}
```

| 字段 | 说明 |
|---|---|
| `values` | 枚举值列表，**按首次出现序**，截断到 `max_values`（缺省 100）；值逐字保留 |
| `value_counts` / `unique_count` | 每值计数与唯一值数，**全量不截断** |
| `original_log` | 每值首条原始日志样本（截断 300 字符），只含 `values` 内的值 |
| `truncated` | `true` 表示值列表被 `max_values` 截断（计数仍全量） |
| `--template` | 另产映射表模板 `enumvalues_{时间戳}.xlsx`：Sheet 名=字段、三列、orgValue 与 EQUAL 预填、mappingValue 留空 |

## 2. 映射对 JSON（宿主 agent 判定产物，填充输入）

```json
{"mappings": [
    {"field": "event_type",
     "pairs": [
        {"orgValue": "login", "mappingValue": "登录"},
        {"orgValue": "attack", "mappingType": "REGULAR"}
     ]}
  ]}
```

| 规则 | 说明 |
|---|---|
| `mappings[].field` | 目标字段名；匹配配置 normalize 条目的 **index 或 field 同名**，全部命中条目都写 |
| `pairs[].orgValue` | 原始值，逐字保留；为空的元素跳过 |
| `pairs[].mappingType` | `EQUAL`（缺省，精确匹配）/ `REGULAR`（正则，未以 `.*` 开头自动加前后缀通配） |
| `pairs[].mappingValue` | 缺省回退（包裹后的）orgValue |
| 裸数组 | 顶层数组视为纯 mappings |
| 原子性 | 非 `mappings` 结构 / 元素缺 `field` / 字段无有效映射对 → `invalid_input` 整单拒绝；重复字段 first-wins 记 `duplicates` |

## 3. 映射表 Excel（用户手工表，填充输入）

- **Sheet 名 = 目标字段名**；前三列按位置读：`mappingType` / `orgValue` / `mappingValue`，首行为列头从第 2 行读起（列头语言不限）
- 归一规则与映射对 JSON 共用（EQUAL 缺省 / REGULAR 包裹 / 回退语义）
- **任一 Sheet 无有效规则 → 整表拒收**（工作簿级原子性）

## 4. 填充/取消产物

**`<输入名>.enumfilled.json` / `<输入名>.enumunmapped.json`**——原配置数组（深拷贝改写）：

- 填充：目标条目 `mappings` 按 orgValue 合并更新（同 orgValue 更新 mappingValue/mappingType、新值追加、未提及保留）；条目外层 value/field/sim 等元数据不动；addFields 里目标字段固定值绑定删除（`%{}` 引用保留，清空的 addFields 条目整体移除）
- 取消：目标条目 `mappings` 置空 `[]`，条目与 field 标注保留

**Base64 导出**——`enummapping_config_{时间戳}.txt`（平台可导入，`--no-export` 跳过）。

## 5. stdout 摘要

| 字段 | 说明 |
|---|---|
| `fields[].targets` | 该目标字段命中的 normalize 条目数 |
| `fields[].added / updated / unchanged / duplicates` | 填充计数：新增 / 原地更新 / 已存在无变化 / 输入内同 orgValue 重复（首现胜出） |
| `fields[].cleared / skipped` | 取消计数：置空条目数 / 本无 mappings 的条目数 |
| `unbound` | 填充时解绑的固定值绑定数 |
| `template` | 提取的映射表模板路径（仅 `--template` 时出现） |

**错误码**：`config_required` / `input_required` / `invalid_config` / `invalid_input` / `enum_extract_empty` / `enum_target_field_mismatch` / `field_not_found` / `field_name_ambiguous` / `mapping_not_found`。守卫命中一律整单拒绝、不产出文件；零变更填充是**成功**（幂等提示，产物照常输出）。**不做目标黑名单**（用户裁决）：任何字段都可经枚举填充/取消维护值映射，包括威胁类型等链路持有字段。
