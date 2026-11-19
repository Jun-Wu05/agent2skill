# 标准字段映射（field-mapping）子模块指南

把解析规则里的原始字段映射到标准字段：你（宿主 agent）负责语义判定（每个字段从候选里挑一个中文标准字段名、每条子规则判一个事件名称），脚本负责候选检索、校验、占用裁决、写回、入口规则生成与导出。两条路径共用一对脚本：

- **B2 白板路径**：log-classification 的白板子规则 → 填映射 + 事件标注 + 入口规则（完整规则链）
- **A6 纯配置路径**：现成解析规则配置 → 只补空字段的映射（既有映射保留不动）

## 何时使用

- 用户要求「字段映射 / 映射到标准字段 / 把 X 映射到 Y / 填白板 / 生成完整（可导入的）解析规则」
- 上一步做过日志类型提取（白板子规则已产出），继续把字段填完
- 用户上传现成配置，要求补齐其中未映射的字段（A6）

## 前置条件

- **B2**：log-classification 产物 `<输入名>.subrules.json` + `<输入名>.classified.json`（见其 guide 第 5 步）；向用户问清**数据源厂商与产品**（入口规则必填，缺失整单拒绝）
- **A6**：配置族文件（Base64 txt / 原生 JSON / TXT，规则数组）
- 标准字段目录（625 条）与同义词/标签资产随技能仓库提供，脚本自动定位，无需用户输入

## B2 标准流程（五步，每步有完成判据）

### 第 1 步：确认输入与版本守卫

收齐白板子规则、分类结果、厂商/产品三样；日志数据 Excel 若在手边一并用于值画像。**版本守卫**：白板子规则若因重新分类被重建过，旧的映射判定已失去依据——先与用户确认作废范围再继续。

**完成判据**：三样输入齐备；白板未被重新生成（或用户已确认作废）。

### 第 2 步：跑候选开单（脚本①）

```bash
python <parser-skills>/field-mapping/scripts/mapping_candidates.py \
  --subrules <输入名>.subrules.json [--excel <日志表.xlsx>]
```

产出 `<输入名>.subrules.candidates.json`：每个待映射字段的 Top-10 候选（附分数/英文名/对象/类型/描述/枚举白名单）+ 值画像（`--excel` 给了用全量日志，否则用白板自带样本）+ 枚举短路标记。

**完成判据**：stdout `status: success`；`field_count` 与白板字段数一致。全部已映射或属排除索引时**成功跳过**（空候选单、`field_count: 0`）——如实告知用户即可。

> `--top-k` 若在阶段①改过，收口（第 4 步）必须传相同值（缺省同为 10）——收口按开单的候选集校验「候选外」降级。

### 第 3 步：语义判定，写 mappings.json

读 candidates.json，**每个字段写一行判定**（`field` + `standard`，两列）：

```json
{"mappings": [
    {"field": "src_ip", "standard": "源地址"},
    {"field": "admin_name", "standard": "未匹配"}
  ],
 "events": [
    {"rule_name": "主机登录_kv_子规则", "event_name": "远程登录"}
  ]}
```

**字段判定硬约束**：

- **只能输出该字段候选列表里的中文系统属性名称**，选不出合适的写「未匹配」——自造名、翻译名、英文名、候选外的名字都会被收口降级为未匹配
- `enum_short_circuit` 非空的字段（8 类枚举目标，如 `http_method`→HTTP请求方法）已确定性命中，**跳过不判**，收口自动填
- 低分候选结合**值画像**判：值全是 IP → 地址类；个位数枚举值 → 枚举类；时间戳/端口/ID 各归各类，不跨类型错配
- 泛化名（`name` / `type` / `id` / `status` / `result`）先看值画像与候选「对象」列再定；同一原始字段在多条子规则共享一个判定（全局判定、逐子规则写回）

**事件名称判定**（events 段，每条子规则一行）：

- 只能写 21 分类名单内的名称**逐字命中**（名单见 `_shared/event_binding.py`：威胁组 6 值 / 非威胁组 15 值），级别由脚本查表绑定（威胁组→提醒，其余→信息）
- 先按规则名+日志类型+样本分威胁/非威胁组，再在组内选类；**拿不准就不写那一行**——宁缺勿错，非法/缺失不写入

**完成判据**：candidates 的每个非短路字段都被覆盖（遗漏会被回填为未匹配并记档）；events 只包含有把握的判定。

### 第 4 步：跑映射收口（脚本②）

```bash
python <parser-skills>/field-mapping/scripts/mapping_finalize.py \
  --subrules <输入名>.subrules.json --classified <输入名>.classified.json \
  --mappings mappings.json --vendor <厂商> --product <产品>
```

产出（均在输入同目录）：

| 产物 | 文件 | 用途 |
|---|---|---|
| 映射后子规则 | `<输入名>.mapped_subrules.json` | 字段映射 + 事件标注写回的子规则 |
| 入口规则 | `<输入名>.entry_rules.json` | 按 logtype 路由到子规则的总闸（本身不含映射） |
| Base64 导出 | `mappedconfig_subrules_YYYYMMDD_HHMM.txt` + `mappedconfig_mainrules_YYYYMMDD_HHMM.txt` | 平台可导入（`--no-export` 跳过） |

**完成判据**：stdout `status: success`。

### 第 5 步：核对摘要

读 stdout 摘要逐项核对：`sanitized`（裁剪/回填/降级——降级明细里出现你判过的名字说明判到了候选外或黑名单，回第 3 步改判重跑）；`conflicts`（两个字段抢同一标准字段被裁决，败者已置未匹配——若你对胜者不认可，改判重跑）；`events`（unknown_rule / invalid_event 有值说明判定写错了规则名或事件名）。

**完成判据**：`sanitized` / `conflicts` / `events` 三处无意外项；匹配成功数与预期一致。

## A6 流程（三步）

1. `python <parser-skills>/field-mapping/scripts/mapping_candidates.py --config <配置文件>`（值画像用配置 normalize 预览值；全部已映射时成功跳过——空候选单，如实告知）
2. 同 B2 第 3 步写 mappings.json（**只写 mappings 段，无 events**——A6 不做事件标注）
3. `python <parser-skills>/field-mapping/scripts/mapping_finalize.py --config <配置文件> --mappings mappings.json`

产物：`<输入名>.mapped_config.json` + `fieldmapped_config_YYYYMMDD_HHMM.txt`。既有映射（field 非空的条目）原样保留且在占用裁决中恒赢。

## 约束与边界

**占用与保留**：一对一占用不变量（一个标准字段只能被一个原始字段占用）由收口脚本裁决——既有映射恒赢 → 精确命中 → 候选相似度 → 原行序；你只管逐字段判定，冲突不需要你预处理。

**黑名单字段**（事件名称/事件级别/日志类型/威胁类型）不会出现在任何候选里：事件名称/级别由本流程事件标注写入，日志类型由日志类型提取写入，威胁类型另有专属链路。

**不支持与边界**：

- **日志头+KV** 格式的入口规则需要日志头正则（feature_identifier），当前分类产物不提供——收口整单拒绝并明示；先用日志头+KV 之外的格式，或与用户商定暂缓
- A6 不做事件标注、不生成入口规则（配置自身已有路由结构）
- 操作类型字段（登录/审计等 7 类的细分）不在本版——事件标注只写事件名称+事件级别
- 枚举字段的**值映射**（如 `GET→成功`）是 enum-mapping 子模块的范围，本流程只判字段归属
- 手动调整已有映射（改判单个字段、清除映射）是独立子命令，另立票据交付
- 产物同名直接覆盖；不原地覆盖输入文件

**完整 JSON 契约**（candidates.json / mappings.json / 两路径产物 / stdout 摘要的字段说明）见 [references/mapping_schema.md](references/mapping_schema.md)。

## 错误码

`config_required`（规则文件缺失）/ `input_required`（判定/分类文件缺失）/ `invalid_config`（规则文件非数组）/ `invalid_input`（路径参数互斥缺失、mappings 契约不符、分类结果非对象、日志头+KV 缺正则、厂商/产品缺失），失败退出码 1，stdout JSON 报告。全部已映射时**不报错**——成功跳过（见各流程步）。
