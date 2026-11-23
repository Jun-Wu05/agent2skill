# field-mapping JSON 契约

五个契约文件 + stdout 摘要的字段说明。脚本对缺失可选字段的容忍度：mappings.json 的 `standard` 缺省视为「未匹配」；其余输入文件字段由脚本严格校验。

## 1. candidates.json（脚本①产物，判定输入）

```json
{
  "fields": [
    {
      "field": "src_ip",
      "enum_short_circuit": null,
      "value_profiles": [
        {
          "owner": "主机登录_kv_子规则",
          "source": "excel",
          "scanned_lines": 10000,
          "hit_lines": 1206,
          "empty_count": 0,
          "distinct_count": 843,
          "values": {"1.2.3.4": 3, "10.0.0.1": 2}
        }
      ],
      "candidates": [
        {
          "name": "源地址",
          "score": 1.0,
          "field_name": "src_address",
          "by_stripped": "",
          "object": "流量,登录",
          "type": "IP",
          "description": "",
          "enum_whitelist": []
        }
      ]
    }
  ]
}
```

| 字段 | 说明 |
|---|---|
| `fields[].field` | 待映射原始字段名（跨子规则 first-seen 保序；已映射与排除索引不出现） |
| `enum_short_circuit` | `null` 或 `{"standard": "HTTP请求方法", "source": "exact\|synonym"}`——非空表示确定性命中，**跳过判定**，收口自动填 |
| `value_profiles[]` | 按 owner（子规则/规则名）分组的值画像；`source`：`excel`（全量日志）/ `sample`（白板样本）/ `config_preview`（配置预览值）；`values` 为计数降序前 10 |
| `candidates[]` | Top-K（缺省 10，`--top-k` 可调，**两阶段须一致**——收口按开单候选集校验「候选外」）候选；`score` 1.0=精确层命中；`by_stripped` 非空表示经去前缀变体命中；黑名单四字段（事件名称/事件级别/日志类型/威胁类型）不出现在任何候选 |

## 2. mappings.json（宿主 agent 判定产物，收口输入）

```json
{
  "mappings": [
    {"field": "src_ip", "standard": "源地址"},
    {"field": "admin_name", "standard": "未匹配"}
  ],
  "events": [
    {"rule_name": "主机登录_kv_子规则", "event_name": "远程登录"}
  ]
}
```

| 规则 | 说明 |
|---|---|
| `mappings[].standard` | 该字段候选列表里的中文系统属性名，或字面量 `未匹配`；候选外/目录外/黑名单名会被收口降级为未匹配并记 `sanitized.degraded` |
| 集合对齐 | 臆造字段名被裁剪（`trimmed`）、遗漏字段回填未匹配（`backfilled`）、重复判定 first-wins（`duplicates`）——均记入 stdout 摘要 |
| `events[]` | 每条子规则至多一行；`event_name` 须 21 分类名单逐字命中；未知规则名/非法事件名跳过不写（摘要记 `events.unknown_rule` / `events.invalid_event`）；配置路径无此段 |
| 裸数组 | mappings.json 顶层数组视为纯 mappings（无 events） |

## 3. 白板路径产物

**`<输入名>_mapped_subrules.json`**——白板子规则数组，收口后每条：

- 命中判定的 normalize 条目：`field`=标准字段目录规范名、`entity`=目录首个对象、`sim`=true、`core`=false
- 未匹配/占用冲突败者：`field`/`entity`/`sim`/`core` 置 null（防重新映射残留）
- 排除索引（original_log / 日志类型）原样保留
- 事件标注（有判定的子规则）：parser.filter 末尾追加 `{"fields": {"事件名称": ..., "事件级别": ...}, "name": "addFields", "id": ""}`；normalize 末尾追加事件名称/事件级别两条目（EQUAL 恒等映射；级别 `value` 写码值、`result` 保持显示值，长度按该子规则样本数）

**`<输入名>_entry_rules.json`**——单元素数组（一条入口规则）：

- `name`：`{厂商}_{产品}_通用_入口规则{MMDD}`；parser 按 log_format 五分支配置（纯JSON：json + conditionMatch + 日志类型映射；syslog+JSON：orgRegex + conditionMatch；纯KV：delimitWithKeyMap + 日志类型映射 + kv conditionMatch；syslog+KV：orgRegex + conditionMatch；其余：orgRegex + redirect）
- `sample`：各 logtype 样本以 `#next#` 连接；normalize 预置 original_log（result=样本列表），纯 JSON/纯 KV 另有「日志类型」占位条目
- `properties`：日志类型（log_type）+ 解析规则链（rule_name_list）+ 数据源三声明（product / log_vendor / data_source）；数据源固定值绑定 addFields 追加在 filter 末尾
- 入口规则本身不含字段映射

## 4. 配置路径产物

**`<输入名>_mapped_config.json`**——原配置数组（递归遍历所有 normalize）：

- 只写 index 命中判定**且原 field 为空**的条目；既有映射（field 非空）原样保留
- 未匹配条目保持原样（field 仍为空）；排除索引不动

## 5. stdout 摘要（两路径共用字段）

| 字段 | 说明 |
|---|---|
| `field_count` / `matched` / `unmatched` | 待映射字段数与裁决后匹配/未匹配计数 |
| `enum_short_circuited` | 枚举短路字段数；`enum_overridden` 列出 agent 也误判了而被短路覆盖的字段 |
| `sanitized` | `{trimmed, backfilled, degraded, duplicates}`；`degraded` 元素含 `reason`（映射目标黑名单 / 目录外名称 / 候选外） |
| `conflicts` | 占用冲突组：`{standard, winner, winner_source(existing\|candidate), losers[]}` |
| `events`（仅白板路径） | `{annotated, unknown_rule[], invalid_event[]}` |
| `output` / `export` | 结果 JSON 与 Base64 导出路径；白板路径另有 `entry_output` / `entry_export` |

**错误码**：`config_required`（规则文件缺失）/ `input_required`（判定/分类文件缺失）/ `invalid_config`（规则文件非数组）/ `invalid_input`（路径互斥缺失、契约不符、日志头+KV 缺 feature_identifier、厂商/产品缺失）。全部已映射时成功跳过（空候选单 / 零匹配产物照常输出），不报错。

## 6. 手动调整契约（mapping_adjust.py）

**CLI**：`--input`（必填）；`--set 字段=标准字段名`（可重复）；`--clear 字段,...`（逗号分隔）；`--target` / `--group`（作用域收窄，target 优先）；`--output`；`--no-export`。`--set` 与 `--clear` 至少给一个，同批目标不得重复、不得重叠。

**目标寻址**：原始字段名（index）或标准字段名（field）同名命中；缺省作用域内全部命中条目一并调整（同名字段跨子规则共享一次调整）。

**`<输入名>_adjusted.json`**——原配置数组（深拷贝改写）：

- set 命中条目：`field`=目录规范名、`entity`=目录首个对象、`sim`=true、`core`=false（四件与收口写回同一来源）
- clear 命中条目：`field`/`entity`/`sim`/`core` 置 null；条目本身与 `mappings` 原样保留——与取消值映射（置空 mappings、标注保留）镜像对称
- 排除索引（original_log/日志类型/事件名称/事件级别）条目不动（set/clear 均拒绝）；未命中的条目不动

**stdout 摘要**：

```json
{
  "status": "success",
  "message": "已设置 1 个条目的归属映射（src_ip→源地址）；已清除 2 个条目的归属映射标注（dst_ip，值映射保留）",
  "output": "...", "export": "...",
  "sets": [
    {"field": "src_ip", "standard": "源地址", "changed": 1, "unchanged": 0, "previous_values": ["目的地址"]}
  ],
  "clears": [
    {"field": "dst_ip", "cleared": 2, "skipped": 0, "previous_values": ["目的地址"]}
  ]
}
```

| 字段 | 说明 |
|---|---|
| `sets[].changed` / `unchanged` | 归属四件实际变化 / 已是目标值的条目数（set 同值幂等成功计 unchanged） |
| `clears[].cleared` / `skipped` | 清除标注 / 本无可清的命中条目数（全部无可清则整单拒绝） |
| `previous_values` | 命中条目的旧归属名清单（去重保序；全空为 `[]`） |

**守卫链（任一命中整单拒绝，一行不写；手动输入显式失败不降级）**：

| 错误码 | 触发 |
|---|---|
| `invalid_input` | 无 --set/--clear；set 规格不符 `字段=标准字段名`；clear 空名单；同批目标重复；同批命中重叠（**按命中条目判定**——经原始字段名与标准字段名双重寻址指向同一条目，set 间或 set/clear 间均拒绝）；标准字段名命中黑名单四字段（报错指引专属链路）；标准字段名不在目录内；set 命中条目已带值映射（提示先取消值映射再改判） |
| `rule_name_not_found` / `event_annotation_required` | `--target` 未知名 / `--group` 无事件标注（复用范围解析底座） |
| `field_not_found` | 目标在作用域内无同名 index/field 条目（附「原始名(标准名)」词汇表） |
| `field_name_ambiguous` | 标准字段名只经 field 命中且对应 ≥2 个原始字段（列出候选，改用原始字段名）；或 set 目标同时经 index 与 field 命中多个不同原始字段（混命中，改用唯一确定的原始字段名） |
| `reserved_field_rejected` | 目标命中排除索引（original_log/日志类型/事件名称/事件级别——审计锚点/链路持有字段） |
| `mapping_target_occupied` | 一对一占用不变量：目标标准字段已被其他原始字段占用（报错指明占用者；占用按调整前状态评估，同批 clear 不解锁，同批多目标指向同一标准字段亦拒绝） |
| `mapping_not_found` | clear 目标命中的全部条目都无可清归属标注（禁止静默成功） |
