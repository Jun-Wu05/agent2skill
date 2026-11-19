# 日志类型提取（log-classification）子模块指南

从 Excel 日志数据表中提取日志类型：你（宿主 agent）负责格式识别、分类特征字段判定与语义归类，脚本负责全量统计、校验、白板子规则装配与导出。产物（白板子规则）是 field-mapping 子模块的输入——不含字段映射的空白子规则，每特征值一条。

## 何时使用

- 用户给出 Excel 日志数据表，要求「区分日志类型 / 把 X 当作日志类型 / 提取日志类型」
- 用户要求从日志数据直接产出可导入平台的（白板）解析规则
- field-mapping 流程的前置步骤（先分类，再映射）

## 前置条件

- 输入是 Excel（.xlsx），第一张工作表、列头含「原始日志」（子串命中，容忍「原始日志（脱敏后）」等变体）；缺列/空表整单拒收（`invalid_input`）
- 环境 openpyxl ≥ 3.1（唯一第三方依赖）

## 标准流程（五步，每步有完成判据）

### 第 1 步：采样识别格式

从「原始日志」列抽 3–5 条看结构，填出四个参数：

| 参数 | 判定要点 |
|---|---|
| `--format` | 行内可解析出 `{...}` JSON 体（**含带 syslog 前缀的**）→ `json`；是 `key=value` / `key:value` 对 → `kv` |
| `--field-delimit` | kv 字段之间的分隔符（空格 / `\|\|` / `;` / `,` / tab） |
| `--kv-delimit` | kv 键与值之间的分隔符（`=` / `:`） |
| `--header-end-marker` | 日志头与日志体的分界标记（识别方法见下）；纯格式留空 |

**格式判定规则**：以每行最外层完整可解析的结构为准，字符串值内部的结构不改变外层判定；有 JSON 体一律按 `json`（不判「混合」「syslog」）。

**`--header-end-marker` 识别方法**：找系统前缀（时间戳/主机名/进程名）结束、日志体开始之前的固定字符串：

- RFC5424：`<14>1 2026-04-14T05:57:55Z host app 1 type - body` → `" - "`
- BSD syslog：`<132>May 18 10:48:52 host fwlog[7992]: 日志类型:IPS` → `": "`
- 自定义：`[2026-06-08] [INFO] content` → `"] "`
- `<数字>` 优先级前缀后**直接跟 KV**（无标准 syslog 结构）→ 空串
- JSON 体（含 syslog 前缀）无需 marker——提取器自带 `{...}` 回退

**完成判据**：四个参数都有值（可为空串），能向用户复述「这是 X 格式、字段分隔 A、键值分隔 B」。

### 第 2 步：判定分类特征字段

按以下清单选一个取值能把日志行分桶的字段（用户点名指定时直接用）：

**1. 强类型字段名优先**：字段名含 `type` / `event_type` / `log_type` / `category` / `class` / `tag_` / `action` / `msg_type`——去重取值 **1~50 个即有效**（常数字段、纯数字值、20+ 种取值都算有效）。

**2. 弱类型字段从严，黑名单排除**：字段名不含上述命名的，去重取值须 **2~20 个**才有效；**>50 个**基本是 ID 类。黑名单（一律不选）：时间戳、IP、端口、MAC、UUID、`session_id`、`request_id`、主机名；数值类字段（`count` / `priority`）默认排除、但字段名含 `type` 时除外。

**3. 用旁证列对照**：Excel 若自带「事件名称」等已归一化的分类列——取「事件名称」相同的几行，看原始日志里哪个字段的取值也跟着一致，即是。

**4. 候选验证（最有效）**：锁定 2~3 个候选字段各跑一次第 3 步的统计（每次几秒、产物同名覆盖），对比报告：`coverage ≥ 0.8`、`value_count` 落在上述区间、取值有语义、分布长尾（少数值占大头）者胜出。

JSON 嵌套结构里，分类字段几乎总在第一层或 `event.*` 浅层；埋在深层的基本不是。

**完成判据**：确定一个特征字段名（JSON 支持点分嵌套路径），且其统计报告通过第 4 条的验证。

### 第 3 步：跑特征统计（脚本①）

```bash
python <parser-skills>/log-classification/scripts/feature_stats.py \
  --input <日志表.xlsx> --format kv --feature-field type \
  [--field-delimit "||"] [--kv-delimit ":"] [--header-end-marker "<标记>"]
```

产出 `<输入名>.stats.json`：每个特征值的计数、样本（≤3 条）、覆盖率、未匹配样本、数据裁决记录。

**完成判据**：`coverage ≥ 0.8` 且 `value_count` 合理。覆盖率低 → 换特征字段或回第 1 步修参数重跑（同名覆盖）。声称的分隔符错了不用慌：脚本的数据裁决会在零匹配时自动探针改判，改判记录在 `adjudications`，读它核对即可。

### 第 4 步：语义归类，写 labels.json

读 stats.json 的 `values`，为**每个特征值**写一行业务含义。`logtype` 必须严格等于统计报告中的特征值——脚本会裁剪臆造值、回填遗漏值（回填的 meaning 为空串，见产物 `sanitized` 字段）：

```json
{"classification_details": [
  {"logtype": "WEAK_PASSWD", "meaning": "弱密码告警"},
  {"logtype": "MALWARE", "meaning": "恶意软件告警"}
]}
```

**完成判据**：stats 的每个特征值都被覆盖；每条 meaning 是一句人话业务解释。

### 第 5 步：跑分类收口（脚本②）

```bash
python <parser-skills>/log-classification/scripts/classify_finalize.py \
  --input <日志表.xlsx> --stats <输入名>.stats.json --labels labels.json
```

产出三份文件（均在输入同目录）：

| 产物 | 文件 | 用途 |
|---|---|---|
| 分类结果 | `<输入名>.classified.json` | 平台兼容 schema，含每类型计数/样本/覆盖率 |
| 白板子规则 | `<输入名>.subrules.json` | 每特征值一条无映射子规则，field-mapping 的输入 |
| Base64 导出 | `unmappedconfig_subrules_YYYYMMDD_HHMM.txt` | 平台可导入（`--no-export` 跳过） |

**完成判据**：stdout `status: success`，`sanitized` 无意外项（有的话回第 4 步补标注重跑）。

## 版本守卫纪律（重新生成前必查）

白板子规则是下游字段映射的基底。**重新跑第 5 步前**，确认下游尚未基于旧分类产出映射结果（`.subrules.json` 衍生的 field-mapping 产物）；已有映射而需要重新分类时，先与用户确认作废范围。

## 约束与边界

- 特征字段位于**日志头**（而非日志体）的场景 v1 不支持——表现为覆盖率极低；此时与用户商定替代方案（如先用 field-adjust 正则提取到独立字段）
- Excel 只读第一张工作表；单元格内换行已清洗为空格，单条日志不会被拆散
- 产物同名直接覆盖；不原地覆盖输入文件
- 三份 JSON 的完整字段说明见 [references/classification_schema.md](references/classification_schema.md)

## 错误码

`input_required`（文件缺失）/ `invalid_input`（缺原始日志列、空表、非 xlsx、labels 契约不符、stats 无特征值），失败退出码 1，stdout JSON 报告。
