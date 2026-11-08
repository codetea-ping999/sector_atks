# sector_atks

業種（セクター）ごとの脅威に合わせて重みづけした **検証済み検知カバレッジ（Verified Detection Coverage, VDC）** を計算するツールとデータです。

「検知ルールがある攻撃技術の割合」ではなく、「実際に試して検知を確認でき、その確認が今も有効な攻撃技術の割合」を、自組織の業種を狙う脅威グループの行動で重みづけして測ります。

```
VDC = Σ_t w_t × V_t                          （t ∈ T、Σ w_t = 1）
V_t = (1 / n_t) × Σ_p ( d_p × f_p )          （p は技術 t で試した手順）
```

| 記号 | 意味 | このリポジトリでの求め方 |
|---|---|---|
| T | 優先技術の集合 | 業種ごとの重み上位 N 技術（既定 20） |
| w_t | 技術 t の重み | ATT&CK のグループ記述から業種を推定し、その業種のグループのうち技術 t を使うグループの割合（任意で CTID の出現頻度と混合） |
| d_p | 手順 p の検知 | 手順 p の最新の結果でアラートが出たら 1。防御だけ（アラートなし）は既定で 0 |
| f_p | 手順 p の鮮度 | その手順の最終検証からの経過日数。既定は 90 日以内なら 1、超えたら 0（指数減衰も選択可） |
| V_t | 鮮度込みの検知率 | 手順ごとの d × f の平均。全手順を同じ日に試した場合は研究ノートの D_t × F_t と一致する |

鮮度は手順ごとに効きます。ある手順の古い成功が、別の手順の最近の失敗によって「最近検証した」扱いになることはありません。

> **注意**：この数値は研究用の試作です。業種の推定や重みには不確かさがあり（[docs/method.md](docs/method.md) の 4〜5 節）、セキュリティ上の意思決定の確定指標としては使わないでください。

定義の背景は研究ノート `06_検証済み検知カバレッジ.md` にあります。詳しい資料は次のとおりです。
- 手法：[docs/method.md](docs/method.md)
- レッドチーム活動との連携（交戦規定・検証計画・証跡の照合）：[docs/redteam_integration.md](docs/redteam_integration.md)
- 参考にしたリポジトリと文献：[docs/references.md](docs/references.md)

## 範囲

このリポジトリは攻撃を実行しません。攻撃の手順、攻撃コード、ペイロードは含めず、検証結果も「どの技術のどのバリエーションを、いつ試し、防御側がどう反応したか」だけを記録します。検証そのものは、権限を持つチームが交戦規定（RoE）の範囲内で、既存のツール（CTID のエミュレーション計画、CALDERA、Atomic Red Team など）を使って行う前提です。sector_atks が受け持つのは次の部分です。
- 脅威に基づく技術の選定
- 検証計画と RoE の検査
- 実行記録と防御側の証跡の突合
- 結果の集計

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

# 3. 隔離ラボでの検証結果を証跡つきで集計する（架空の例）
python3 -m sector_atks check-roe examples/lab_engagement/roe.json
python3 -m sector_atks match-evidence --roe examples/lab_engagement/roe.json \
  --runs examples/lab_engagement/runs.csv --alerts examples/lab_engagement/alerts.csv \
  --logs examples/lab_engagement/logs.csv --verifier blue-lead -o out/lab_validations.csv
#   （例では範囲外ホストの実行 R-006 を除外して終了コード 1 を返す）
python3 -m sector_atks vdc --weights examples/lab_engagement/weights.csv \
  --validations out/lab_validations.csv --plan examples/lab_engagement/plan.csv --as-of 2026-11-07

# 4. 業種の上位技術に対応する公開エミュレーション計画を一覧にする
python3 -m sector_atks plan-candidates --weights data/attack-v20.0/weights/finance.csv \
  --group-sectors data/attack-v20.0/group_sectors.csv --sector finance

# 5. 重みを作り直す（ATT&CK の新版が出たとき）
python3 -m sector_atks fetch-attack --version 20.0 -o cache/enterprise-attack.json
python3 -m sector_atks build-weights --stix cache/enterprise-attack.json \
  --out-dir data/attack-v20.0 --overrides data/group_sector_overrides.csv
```

出力されるもの：

- VDC、検証計画の実施率、自己申告カバレッジとの差（申告ギャップ）
- 回帰率（検知能力の低下）と鮮度の負債（検証の失効）を別々に表示した値、改善速度（失敗した手順が検知できるようになるまでの平均日数）
- 検知率・防御率・ログ率（可視性）を別々に集計した値と、証跡がないため数えなかった件数
- 優先度順の技術一覧（残り = w × (1 − V) の大きい順。どこから直すと VDC が最も上がるか）
- `--layer` で ATT&CK Navigator のレイヤー（スコア = V）

既定では、証跡（event_id か evidence_uri）と確認者（verifier）のそろったアラートだけを検知に数えます。防御されたがアラートが出なかった結果も数えるには `--count-prevented` を、自己申告の結果も数えるには `--allow-unverified` を付けます。検証計画（`--plan`）を渡すと、未実施の計画手順を未検知として数えます。

### 入力ファイルの形式

`validations.csv`（検証記録）

| 列 | 内容 |
|---|---|
| technique_id | ATT&CK 技術 ID。サブ技術（T1059.001）は親技術に集計される |
| procedure_id | 手順バリエーションの識別子（例：社内の試験 ID。手順の中身は書かない） |
| tested_on | 検証日（YYYY-MM-DD） |
| outcome | `prevented`（防御された）／`detected`（検知された）／`logged`（ログのみ）／`none`（ログなし） |
| notes | 任意のメモ |
| prevented, alerted, logged | 任意。`true`／`false`。防御・アラート・ログの有無を個別に記録する。空欄なら outcome から決まる |
| run_id, rule_id, event_id, evidence_uri, verifier | 証跡。`match-evidence` が埋める。event_id か evidence_uri と、verifier がないと検知に数えない |

outcome から決まる既定値は次のとおりです。`prevented` はアラートもログも「なし」として扱うので、実際にあった場合は列で明示してください。

| outcome | prevented | alerted | logged |
|---|---|---|---|
| prevented | true | false | false |
| detected | false | true | true |
| logged | false | false | true |
| none | false | false | false |

同じ technique_id と procedure_id の組は最新の結果だけが使われます。過去の結果は回帰率と改善速度の計算に使われます。

`claimed.csv`（自己申告）は `technique_id,has_rule`、重みファイルは `technique_id,name,weight` です。weight が空の行は優先集合外として無視します。負数・NaN・無限大・数値でない値・technique_id の重複はエラーになります。

## 同梱データ

`data/attack-v20.0/`（ATT&CK Enterprise v20.0、2026-10-13 版から生成）

| ファイル | 内容 |
|---|---|
| `group_sectors.csv` | グループと業種の対応。根拠の語句、根拠の文、ATT&CK のページ付き（178 グループ中 110 グループに付与） |
| `untagged_groups.csv` | 業種を付けられなかった 68 グループ |
| `weights/<業種>.csv` | 業種ごとの技術の順位、使用グループ数、割合、リフト、重み |
| `weights/_all_groups.csv` | 全グループで作った基準の重み（業種を問わない場合や比較に使う） |
| `sector_summary.csv` | 業種ごとのグループ数、少数フラグ、基準との重なり、ブートストラップ安定度、上位 5 技術 |
| `log_sources.csv` | ATT&CK v18 以降の検知戦略・分析から抽出した、技術ごとのログソース（可視性の切り分けに使う） |
| `build_info.json` | 生成条件 |

業種は 13 区分（金融、政府・行政、防衛・航空宇宙、エネルギー、医療・製薬、通信、IT・テクノロジー、製造、教育・研究、運輸・物流、小売・宿泊・飲食、メディア、NGO・市民社会）です。判定はキーワードによる自動推定なので、`data/group_sector_overrides.csv` に `group_id,sector,action`（add／remove）で手動修正を足せます。

`data/ctid/top_attack_prevalence.csv` は CTID Top ATT&CK Techniques（Apache-2.0）の prevalence_score を抜き出したもので、`build-weights --prevalence ... --beta 0.3` のように混合に使えます。

データの出典と利用条件は [data/README.md](data/README.md) にあります。

## テスト

```sh
python3 -m unittest discover -s tests
```
