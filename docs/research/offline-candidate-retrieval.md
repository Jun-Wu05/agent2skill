# 标准字段候选检索的离线化调研

> 调研对象：ToolWithAgent 克隆（`C:\Users\v-wujun\AppData\Local\Temp\ToolWithAgent`，下称「工作台」）。
> 目的：评估「标准字段映射」的候选检索链路中哪些环节确定性、哪些依赖外部 API（SiliconFlow Embedding），以及改造为独立 Agent Skill（零外部 LLM/embedding API）时的离线候选检索替代方案。
> 引用格式：`文件:行号`，均相对克隆仓库根目录。

## 1. 现状链路：从原始字段名到候选标准字段列表

公共入口是 `batch_retrieve_candidates`（`agent/core/field_retriever.py:932`，markdown 出口）与 `batch_retrieve_candidates_table`（`agent/core/field_retriever.py:825`，结构化出口 `CandidateTable`，`field_retriever.py:602-606`）。`application/field_runtime.py:3-5` 只是二者的再导出。完整链路：

1. **加载/初始化语料缓存**（`field_retriever.py:624-639` `_load_embedding_records`）：
   - 从磁盘读 `标准字段_embeddings.npy` + `标准字段_records.json`（路径定义 `field_retriever.py:78-79`）；缓存不存在时 `init_field_cache`（`field_retriever.py:301-377`）分批调 embedding API 重建，并以 schema 版本 + 字段表/标签规则/同义词表 MD5 + 模型/维度六重校验决定是否刷新（`field_retriever.py:315-354`）。
   - **排除逻辑**：`_apply_mapping_exclusions`（`field_retriever.py:572-599`）按映射目标黑名单 `MAPPING_EXCLUDED_STANDARD_FIELDS`（事件名称/事件级别/日志类型/威胁类型，`agent/tools/rule_generator/field_mapping.py:28-30`）同步剔除记录行与嵌入行。
2. **构造查询文本**（`_build_query_text_for_embedding`，`field_retriever.py:479-502`）——全部确定性：
   - 英文缩写展开 `_expand_field_name`（`field_retriever.py:120-140`）：camelCase/kebab 拆 token 后逐个查 `field_synonyms.json` 的 `en` 字段，另有整名复合 key 回退（`field_retriever.py:135-139`）。
   - 标签 `_generate_field_tags`（`field_retriever.py:89-117`）：token 拆分后与 `tag_rules.json` 关键词集合求交集，任一命中即打标。
   - **中文同义词桥接** `_collect_zh_synonyms`（`field_retriever.py:447-476`）：逐 token 及复合 key 收集 `zh` 别名补进查询文本，弥补 embedding 模型中英跨语言对齐不足（注释见 `field_retriever.py:449-452`）。
3. **查询向量生成**（`embed_query_texts`，`agent/core/embedding_client.py:166-208`）：保序去重 + 进程内 `QUERY_EMBEDDING_CACHE`（`embedding_client.py:159-163`），miss 批次调 **SiliconFlow API**（`call_embedding_api`，`embedding_client.py:53-153`；模型 `Qwen/Qwen3-Embedding-8B`、dim 4096、batch 15、批间 0.3s、超时 30s、重试 1 次，`embedding_client.py:21-28`）。嵌套字段（含 `.`）还额外生成去前缀变体并整批嵌入（`_collect_stripped_variants`，`field_retriever.py:659-690`；变体规则 `_strip_field_prefix`，`field_retriever.py:505-524`）。
4. **相似度矩阵**：L2 归一化后 `np.dot`（`field_retriever.py:866-870`），数学计算确定性。
5. **候选收集（多层）**：
   - **Layer 1/1.5 精确匹配**（`_collect_exact_candidates`，`field_retriever.py:693-745`）：用规范化名/紧凑名（`normalize_field_name`/`compact_field_name`，`agent/core/standard_field_catalog.py:30-41`）查 `build_name_index` 建的索引（`standard_field_catalog.py:150-178`）。索引除英文字段名的两级 key 外，还注册**中文系统属性名直接作 key** 与 **synonyms.zh 反向索引**（`standard_field_catalog.py:166-177`），使中文 query 可精确命中 sim=1.0 置顶（注释见 `field_retriever.py:411-424`）。确定性。
   - **Layer 2/2.5 语义检索**（`_collect_semantic_candidates`，`field_retriever.py:748-806`）：主字段与去前缀变体各自的 top-K（`_top_k_indices`，`field_retriever.py:616-621`），低于 `SIMILARITY_THRESHOLD = 0.15`（`field_retriever.py:59`）的丢弃，与精确层去重。相似度本身来自第 3 步的 API 向量。
6. **Token 重排序**（`_rerank_candidates`，`field_retriever.py:809-822`）：排序键为（tier: 精确=0/其余=1，token 重叠数降序，相似度降序），tier 用 `sim >= 0.999` 判精确（`field_retriever.py:819`）。重叠 token 来自两端各自 `_expand_field_name` 展开（`field_retriever.py:143-145`）。确定性。
7. **渲染**：markdown（`render_candidates_markdown`，`field_retriever.py:905-929`）或附目录元数据（对象/类型/枚举白名单/描述）的增强版（`render_candidates_enriched`，`field_retriever.py:955-1007`）。确定性。

**下游分工（与 Skill 化直接相关）**：

- 候选注入 prompt：`FieldMappingAdapter._build_prompt_prequery`（`application/adapters/field_mapping.py:95-117`）把结构化候选表渲染为增强文本，每批只调一次检索器（`application/field_mapping_batch.py:174,308`）。
- 宿主 LLM 判断：`agent/prompts/field_weak.md:13,18` 硬约束「只能输出候选列表里的中文系统属性名称，候选已由系统预查询注入，不得额外调用工具查询」；`:19-20` 要求低分候选结合值类型/语义规则谨慎判断。
- 应用映射与冲突裁决（确定性）：`apply_field_mapping_to_sub_rules` / `apply_field_mapping_to_config`（`field_mapping.py:75-206`）把 LLM 输出经 `resolve_standard_field`（`field_mapping.py:33-46`，目录确定性 lookup）写回；一对一占用冲突由 `application/field_mapping_conflicts.py`（`_choose_new_winner` 按精确命中→相似度→原行序选保留行，`:70-80`）确定性裁决。此外 8 个枚举字段走纯规则自动映射（`resolve_enum_field`，`standard_field_catalog.py:305-340`），完全不经过 LLM/embedding。

## 2. 确定性 / API 依赖分界

| 环节 | 位置 | 属性 |
|---|---|---|
| 标准字段表/同义词表/标签规则解析与 lookup | `standard_field_catalog.py:93-178,343-346` | 确定性 |
| Layer 1/1.5 精确匹配（含中文别名反向索引） | `field_retriever.py:693-745` | 确定性 |
| 同义词展开 / 标签生成 / 中文桥接文本构造 | `field_retriever.py:89-140,447-502` | 确定性 |
| 映射黑名单排除 | `field_retriever.py:572-599` | 确定性 |
| Token 重排序 / 渲染 | `field_retriever.py:809-822,905-1007` | 确定性 |
| 语料 embedding 缓存构建（miss 时） | `field_retriever.py:250-298`（调 `embedding_client.py:53-153`） | **依赖外部 API**（一次性，可持久化） |
| 查询向量生成（含去前缀变体轮） | `embedding_client.py:166-208`；`field_retriever.py:678-682,860-864` | **依赖外部 API**（每批新字段名） |
| Layer 2/2.5 相似度分数 | `field_retriever.py:748-806`（消费向量） | 数值来自 API 向量 |
| LLM 候选判断 | `field_weak.md`（注入候选后） | 依赖外部 LLM（Skill 化后由宿主 agent 承担） |
| 冲突裁决 / 映射写回 / 枚举自动映射 | `field_mapping_conflicts.py`；`field_mapping.py:75-206`；`standard_field_catalog.py:305-340` | 确定性 |

即：**链路里唯一必须联网的点是向量生成**（语料端可缓存、查询端不可避）。其余环节——包括同义词桥接、标签、精确匹配、重排、冲突裁决——已经是纯本地规则。

## 3. 数据资产盘点

- **`config/标准字段.txt`**：TSV，7 列（系统属性名称/属性分类/字段名称/属性类型/描述/枚举值/对象），共 **625 条记录** + 头行（实测 626 行；`field_retriever.py:9` 注释称 654 为旧数据）。每条天然带中文系统名 + 英文字段名 + 中文描述，本身就是现成的双语检索语料。
- **`config/field_synonyms.json`**：**264 个条目**，每条 `{en: 英文全称, zh: [中文别名]}`；**206 条带中文别名，共 488 个 zh 别名**；**133 个条目 key 含下划线（复合 key，如 `src_ip`）**；78 条 `en == key`（纯中文桥接用途）。覆盖方式：**token 级精确匹配**（小写 token 查 dict）+ **整名复合 key 回退**（`field_retriever.py:133-139`），**不做子串匹配**。
- **`config/tag_rules.json`**：**22 个标签**（source/destination/network/address/port/…/ioc），每标签一组关键词（合计约 90 个），**token 级匹配**，设计上避免子串误伤（文件头注释 `tag_rules.json:2`）。
- 三份资产互相独立的 MD5 已纳入缓存失效逻辑（`field_retriever.py:316-337`），说明它们是可独立演化的「事实表」。

## 4. 离线候选检索方案对比（625 条规模）

### 方案 A：同义词表 + tag_rules 纯词法评分（推荐基座）

做法：保留现有 Layer 1 精确匹配（规范化名/紧凑名/中文系统名/zh 别名反向索引），语义层改为对 625 条目录逐条计算词法分数：查询端 `_expand_field_name` + `_collect_zh_synonyms` 生成的中英 token 集，与索引端每条的（展开英文名 + 标签 + 中文系统名分词 + 描述关键词）求重叠/Jaccard，叠加上限为 1.0 的 difflib.SequenceMatcher 字符相似度兜底（Python 标准库），最后套用现有 `_rerank_candidates` 排序。

- 优点：零新增依赖（纯标准库）；完全复用既有确定性组件与数据资产；可解释、可单测；中文桥接经 zh 反向索引和系统名分词保留。
- 缺点/召回风险：词面不同义的映射（如 `tenant`→租户、`ja3`→TLS 指纹、缩写不在 264 条同义词表内）会漏。风险对冲：625 条规模极小，Top-K 从 5 放宽到 10，把「正确答案不在候选里」的概率换算为宿主 LLM 的额外甄别成本——prompt 已有「低分候选可结合值类型选」的约束（`field_weak.md:19`），低置信候选交给 LLM 是设计内路径。
- 成本：约 150–250 行 Python；数据资产原样搬入 Skill。

### 方案 B：字符相似度主导（difflib / 编辑距离 / 共现 token）

做法：不建索引，对每个 query 与 625 条的英文字段名（含 normalize/compact 变体）+ 中文系统名直接算 `difflib.SequenceMatcher` 比率排序。

- 优点：实现最简（几十行）；对拼写变体（`srcip` vs `src_ip` compact 归一后已解决）、前后缀命名（`eventSrcIp`）天然鲁棒。
- 缺点：纯字面信号，跨语言（英文名 vs 中文名）完全无能为力（需方案 A 的桥接弥补）；`name/type/status` 这类高频 token 会产生大量同分并列，区分度差；单独使用召回质量明显低于 A。
- 定位：适合作为 A 的分数分量而非独立方案。

### 方案 C：本地轻量 embedding（fastembed / sentence-transformers + 离线模型文件）

做法：Skill 内置一个 ~100–400MB 的多语小模型（如 bge-small-zh-v1.5 / multilingual-e5-small，ONNX 经 fastembed 加载），一次性预计算 625 条复合文本向量（沿用 `_composite_text` 构造，`field_retriever.py:158-172`）随 Skill 分发，运行时只编码 query（毫秒级）。

- 优点：语义召回最接近现状（现链路已证明 embedding 对「字面不同义」场景的价值）；查询端零网络；语料端可随 Skill 预生成，运行时无冷启动成本。
- 缺点：违背「零外部依赖」的极简诉求（模型文件体积、框架依赖）；本地小模型（384 维）与 Qwen3-Embedding-8B（4096 维）召回有差距，中英跨语对齐取决于选型；模型文件使 Skill 变重，且「离线模型文件从哪来」本身需要一个分发/缓存约定。
- 成本：依赖注入 + 缓存格式 + 失效逻辑移植，约 300–400 行 + 资产体积。

## 5. 推荐方案

**推荐方案 A（同义词表 + tag_rules 词法打分 + difflib 兜底），把方案 C 留作可选增强层**。理由：

1. 625 条的语料规模下，全量词法打分是微秒级操作，根本不需要近似检索结构；瓶颈在召回而非性能。
2. 现有链路已经证明最有效的信号——精确匹配置顶、同义词桥接、token 重排序——全部是确定性的，只有 Layer 2 的向量分数来自 API。方案 A 精确保留全部确定性组件，仅替换向量分数这一项。
3. Skill 的宿主 agent 本身是 LLM：把 Top-K 放宽到 10 并附目录元数据（对象/类型/描述/枚举，复用 `render_candidates_enriched` 的格式），「候选稍噪」的代价由宿主 LLM 的判断力吸收；而「完全漏召回」才是致命的，这一风险已通过 zh 别名反向索引 + 中文系统名检索 + difflib 兜底三层对冲。
4. 若后续实测发现漏召回集中在特定类别，再按需引入 fastembed 作为可插拔的第三层（接口对齐 `CandidateRetriever` 签名 `field_mapping_conflicts.py:20` 即可），不推翻基座。

**嵌入「脚本产出候选 → 宿主 agent 判断 → 脚本裁决占用冲突」的分工**：

- **脚本（Skill，确定性）**：产出 `原始字段名 → Top-10 候选(分数, 英文名, 对象, 类型, 描述, 枚举白名单)`；同时先跑 `resolve_enum_field`（`standard_field_catalog.py:305-340`）把 8 个枚举字段直接确定性短路，不进 LLM。
- **宿主 agent（LLM，判断）**：拿到候选表 + 值画像，按 `field_weak.md` 同款硬约束从候选内选择或输出未匹配；无网络、无工具调用。
- **脚本（裁决）**：LLM 输出回脚本后，`resolve_standard_field` 做目录内确定性解析（拒绝自造名），再按一对一占用冲突的确定性规则（精确命中 → 分数 → 行序，`field_mapping_conflicts.py:70-80`）裁决胜者并写回，黑名单字段（事件名称/事件级别/日志类型/威胁类型）在候选阶段即被排除。

该分工使 Skill 的每一处「智能」都有 LLM 兜底、每一处「落盘」都有确定性校验，符合无外部 API 的约束。
