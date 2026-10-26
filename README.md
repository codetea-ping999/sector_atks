# sector_atks

業種（セクター）ごとの脅威に合わせて重みづけした **検証済み検知カバレッジ（Verified Detection Coverage, VDC）** を計算するツールとデータです。

「検知ルールがある攻撃技術の割合」ではなく、「実際に試して検知を確認でき、その確認が今も有効な攻撃技術の割合」を、自組織の業種を狙う脅威グループの行動で重みづけして測ります。

```
VDC = Σ_t ( w_t × D_t × F_t )      （t ∈ T、Σ w_t = 1）
```

| 記号 | 意味 | このリポジトリでの求め方 |
|---|---|---|
| T | 優先技術の集合 | 業種ごとの重み上位 N 技術（既定 20） |
| w_t | 技術 t の重み | ATT&CK のグループ記述から業種を判定し、その業種のグループのうち技術 t を使うグループの割合（任意で CTID の出現頻度と混合） |
| D_t | 頑健性込みの検知率 | 試した手順（バリエーション）のうち、最新の結果が検知・防御だった割合 |
| F_t | 鮮度 | 最終検証からの経過日数。既定は 90 日以内なら 1、超えたら 0（指数減衰も選択可） |

定義の背景は研究ノート `06_検証済み検知カバレッジ.md` にあります。手法の詳細は [docs/method.md](docs/method.md)、参考にしたリポジトリと文献は [docs/references.md](docs/references.md) を見てください。

## 範囲

このリポジトリは防御側の測定に限ります。攻撃の手順、攻撃コード、ペイロードは含めず、検証結果も「どの技術のどのバリエーションを、いつ試し、防御側がどう反応したか」だけを記録します。検証そのものは、組織が許可した範囲で既存の手段（パープルチーム演習、BAS、記録済みテレメトリへのルール適用など）で行う前提です。

## 使い方

Python 3.10 以上、外部ライブラリは不要です。

```sh
# 1. 架空組織の例（研究ノートの計算例。VDC = 50%）
python3 -m sector_atks vdc \
  --weights examples/fictional_org/weights.csv \
  --validations examples/fictional_org/validations.csv \
  --claimed examples/fictional_org/claimed.csv \
  --as-of 2026-10-26 --previous-as-of 2026-08-31

# 2. 業種別の重み（同梱済み、ATT&CK v20.0）を使う
python3 -m sector_atks vdc \
  --weights data/attack-v20.0/weights/finance.csv \
  --validations あなたの検証記録.csv --as-of 2026-10-26 \
  --json out/report.json --layer out/layer.json --attack-version 20

# 3. 重みを作り直す（ATT&CK の新版が出たとき）
python3 -m sector_atks fetch-attack --version 20.0 -o cache/enterprise-attack.json
python3 -m sector_atks build-weights --stix cache/enterprise-attack.json \
  --out-dir data/attack-v20.0 --overrides data/group_sector_overrides.csv
```

出力されるもの：

- VDC、自己申告カバレッジとの差（申告ギャップ）、可視性、回帰率、改善速度（失敗した手順が検知できるようになるまでの平均日数）
- 優先度順の技術一覧（残り = w × (1 − D × F) の大きい順。どこから直すと VDC が最も上がるか）
- `--layer` で ATT&CK Navigator のレイヤー（スコア = D × F）

### 入力ファイルの形式

`validations.csv`（検証記録）

| 列 | 内容 |
|---|---|
| technique_id | ATT&CK 技術 ID。サブ技術（T1059.001）は親技術に集計される |
| procedure_id | 手順バリエーションの識別子（例：社内の試験 ID。手順の中身は書かない） |
| tested_on | 検証日（YYYY-MM-DD） |
| outcome | `prevented`（防御された）／`detected`（検知された）／`logged`（ログのみ）／`none`（ログなし） |
| notes | 任意のメモ |

同じ technique_id と procedure_id の組は最新の結果だけが使われます。過去の結果は回帰率と改善速度の計算に使われます。

`claimed.csv`（自己申告）は `technique_id,has_rule`、重みファイルは `technique_id,name,weight`（weight が空の行は優先集合外として無視）です。

## 同梱データ

`data/attack-v20.0/`（ATT&CK Enterprise v20.0、2026-10-13 版から生成）

| ファイル | 内容 |
|---|---|
| `group_sectors.csv` | グループと業種の対応。根拠となった記述の語句付き（178 グループ中 113 グループに付与） |
| `weights/<業種>.csv` | 業種ごとの技術の順位、使用グループ数、割合、リフト、重み |
| `sector_summary.csv` | 業種ごとのグループ数と上位 5 技術 |
| `log_sources.csv` | ATT&CK v18 以降の検知戦略・分析から抽出した、技術ごとのログソース（可視性の切り分けに使う） |
| `build_info.json` | 生成条件 |

業種は 13 区分（金融、政府・行政、防衛・航空宇宙、エネルギー、医療・製薬、通信、IT・テクノロジー、製造、教育・研究、運輸・物流、小売・宿泊・飲食、メディア、NGO・市民社会）です。判定はキーワードによる自動推定なので、`data/group_sector_overrides.csv` に `group_id,sector,action`（add／remove）で手動修正を足せます。

`data/ctid/top_attack_prevalence.csv` は CTID Top ATT&CK Techniques（Apache-2.0）の prevalence_score を抜き出したもので、`build-weights --prevalence ... --beta 0.3` のように混合に使えます。

データの出典と利用条件は [data/README.md](data/README.md) にあります。

## テスト

```sh
python3 -m unittest discover -s tests
```
