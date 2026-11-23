# 威胁类型链路（threat-type）子模块指南

给已判定为威胁组的子规则补全【威胁类型】字段与值映射：你（宿主 agent）负责来源字段判定与威胁分类，脚本负责圈定、画像、覆盖校验、写回与导出。两个脚本各管一事：

- **工作单**（threat_worklist.py）：配置 + 日志表 → 威胁子规则清单、候选字段值画像、威胁类型白名单
- **收口**（threat_finalize.py）：分组判定 JSON → 覆盖校验 + 删旧加新 + 映射写入（原子幂等）

## 何时使用

- 用户说「映射到威胁类型 / 给威胁子规则加威胁类型 / 补全威胁类型」→ 本链路
- 字段映射收口判出威胁子规则后，用户要求续跑威胁链路 → 本链路（先确认配置已带事件标注）
- 用户给**手工整理的威胁类型映射表**要直接填充 → 走 enum-mapping 的填充（两者共用 orgValue 合并语义，可共存）

## 前置条件

- 配置族文件（Base64 txt / 原生 JSON / TXT，规则数组），其中**威胁子规则已标注【事件名称】**（威胁组 6 分类：网络攻击/病毒检测/邮件告警/终端告警/蜜罐告警/其他告警）——链路目标按威胁组自动寻址，不支持点名子规则
- 日志数据 Excel（第一张工作表须含「原始日志」列）；你先看样本判日志体格式与分隔符（判定规则同日志类型提取指南第 1 步）

## 标准流程（四步，每步有完成判据）

### 第 1 步：确认格式

从日志样本判格式：纯 JSON / syslog 头+JSON / 纯 KV / syslog 头+KV，KV 另判字段与键值分隔符。

**完成判据**：格式与分隔符结论明确。

### 第 2 步：跑工作单（脚本①）

```bash
python <parser-skills>/threat-type/scripts/threat_worklist.py \
  --input <配置文件> --log <日志表.xlsx> --format json|kv \
  [--field-delimit <字段分隔符>] [--kv-delimit <键值分隔符>] \
  [--header-end-marker <日志头标记>] [--max-values 100]
```

产出 `<输入名>.threat_worklist.json`：威胁子规则名单、每条子规则威胁类型字段现状（absent/chain/existing 三态）、每个候选字段的全日志值画像（唯一值数、首现值列表、计数、首条样本、无语义数字代码标记）、威胁类型白名单。

**完成判据**：stdout `status: success`。`event_annotation_required`＝配置没有任何事件标注（先做事件标注）；`rule_name_not_found`＝有标注但无威胁组成员。

### 第 3 步：来源字段判定 + 威胁分类，产出分组判定 JSON

**来源字段判定（逐子规则，同名字段自动归组）**——对每条威胁子规则，在其字段池里选「值语义是威胁分类描述」的字段：

- **值画像硬信号**：唯一值少（约 1~50）且样本为告警语义文本（如「挖矿行为」「暴力破解」）为强信号；样本全为 IP/数字代码/时间戳的字段排除；`all_code_only` 的字段排除
- 来源字段同名的子规则自动归为一组（全同名＝单组最常见情形；异构字段名各自成组，不取交集）
- **拿不准就问**：多条候选难分时，把字段名+值样本交用户裁决；判不出且用户不愿点名的子规则放进 `skipped_rules`（如实记录，不静默跳过）

**威胁分类（对各组来源值的并集逐值写映射行）**：

```json
{"groups": [
    {"source_field": "threat_name",
     "rules": ["恶意软件规则", "Web攻击规则"],
     "pairs": [
        {"mappingType": "REGULAR", "orgValue": "(?i).*挖矿.*", "mappingValue": "挖矿木马"},
        {"mappingType": "EQUAL", "orgValue": "4457", "mappingValue": "端口扫描"}
     ]}
  ],
 "skipped_rules": ["某规则"]}
```

**分类硬约束**：

- `orgValue` 用 REGULAR 风格 `(?i).*关键词.*`，关键词＝从告警值提取的核心威胁词（工具名/病毒名/行为名）；精确对应时可用 EQUAL 逐字
- `mappingValue` 只能取工作单 `whitelist`（标准字段目录威胁类型枚举值），严禁自造值
- 匹配优先级：精确命中非「其他」项 → 最细粒度语义命中（有具体类不落父类）→ 宽泛类兜底 → **「其他」仅作绝对最后手段**
- 同一声明值只允许被一行命中（正则不得重叠）；每组映射行集合与其来源值集合**一致**：不新增、不遗漏、不合并
- 值域与威胁类型整体不兼容（如纯数字代码）→ 告知用户换来源字段或提供代码表，禁止按直觉猜测

**完成判据**：每条威胁子规则都进了某个 group 或 `skipped_rules`；每个 `mappingValue` 都在白名单内；每组 pairs 恰好覆盖该组来源值。

### 第 4 步：跑收口（脚本②）

```bash
python <parser-skills>/threat-type/scripts/threat_finalize.py \
  --input <配置文件> --worklist <工作单.json> --judgments <分组判定.json>
```

产出 `<输入名>.threatfilled.json` + Base64 导出 `threatmapping_config_{时间戳}.txt`。

**完成判据**：stdout `status: success`；核对 `groups` 摘要（每条子规则的 state / added / updated / unbound）。被拒时按错误信息修正分组判定后重跑（一行都不会写，安全重试）。

## 约束与边界

- **统一覆盖校验，整单拒绝**（一行不写）：映射目标值枚举外 / 声明值缺行 / 正则重叠 / 多余行 → `threat_mapping_coverage_rejected`（报错指明具体值/行）；修正判定后重跑即可
- **三态写回**：子规则已有链路自产的【威胁类型】（带 `%{来源字段}` 引用绑定）→ 重跑整体替换、mappings 全量重建（内容幂等）；存量条目（他方写入）→ 保留条目、orgValue 合并；无条目 → 新增条目 + 引用绑定（`field=threat_type / entity=威胁 / sim=true / core=false`）
- **值画像为全日志口径**：候选字段值取自全部日志行，不区分子规则行归属——异构分组时某组的声明值可能含该组日志中未出现的值，分类照常覆盖即可
- 威胁子规则判不出来源字段 → 不降级、不静默加固定值；请用户点名来源或确认跳过。用户明确要「全部落其他」→ 用 field-adjust 的 add 固定值（`--group threat`）
- 覆盖校验的声明值集来自工作单（value_counts 全量键）；配置在开单后修改过 → 收口报不一致，重新生成工作单
- 产物同名直接覆盖；不原地覆盖输入文件

**完整 JSON 契约**（工作单 / 分组判定 / 产物 / stdout 摘要的字段说明）见 [references/threat_schema.md](references/threat_schema.md)。

## 错误码

`config_required`（配置文件缺失）/ `input_required`（日志表或工作单缺失）/ `invalid_config`（配置非数组）/ `invalid_input`（结构不符、分组不成立、来源字段不在候选或字段池、工作单与配置不一致）/ `event_annotation_required`（无事件标注）/ `rule_name_not_found`（无威胁组成员）/ `threat_mapping_reference_unavailable`（标准目录威胁类型行异常）/ `threat_mapping_source_context_required`（声明值全为无语义数字代码）/ `threat_mapping_coverage_rejected`（覆盖校验四规则，附规则标识），失败退出码 1，stdout JSON 报告。
