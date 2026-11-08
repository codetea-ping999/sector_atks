# レッドチーム活動との連携設計

## 1. 位置づけ

sector_atks は攻撃を実行しません。脅威インテリジェンスからの技術の選定、検証計画と交戦規定（RoE）の管理、実行記録と防御側の証跡の突合、VDC の計算を受け持ちます。攻撃エミュレーションそのものは、権限を持つチームが既存のツール（CTID のマイクロエミュレーション計画、CALDERA、Atomic Red Team、社内の試験手順など）を使い、RoE に書いた範囲と期間の中で行います。

```
脅威インテリジェンス（ATT&CK・業種別の重み）
   │  build-weights / plan-candidates
   ▼
検証計画（plan.csv）と交戦規定（roe.json）   ← check-roe
   │
   ▼
承認済みのエミュレーション（外部ツール・隔離環境）── 実行記録 runs.csv
   │                                                 │
   ▼                                                 ▼
防御側（SIEM/EDR）── アラート alerts.csv・ログ logs.csv ──► match-evidence
                                                     │
                                                     ▼
                                    validations.csv（証跡つき）
                                                     │  vdc --plan
                                                     ▼
                         VDC・実施率・鮮度の負債・回帰率・優先度 → 改善・再検証
```

この分担にした理由は三つあります。
1. **安全性**：攻撃コードを公開リポジトリに置かない。実行は、停止条件とログ保全を備えた、承認済みの環境とツールに任せる。
2. **独立性**：検知の判定を、実行した側の自己申告ではなく、防御側のツールが記録したイベントで裏づける。
3. **再利用**：検証の中身は CTID などの公開されたエミュレーション計画を参照し、車輪の再発明をしない。

## 2. 交戦規定（`roe.json`、`check-roe`）

| 項目 | 内容 | 検査 |
|---|---|---|
| engagement_id, objective | 識別子と目的 | 必須 |
| authorized_by, authorization_ref | 承認者と承認記録の番号 | 必須 |
| environment | `isolated-lab` または `approved-production` | 他の値は不可。本番の場合は `production_approval_ref` も必須 |
| scope.hosts（scope.networks） | 試験してよいホスト | hosts は空にできない |
| window.start / end | 実施期間（UTC オフセット必須） | end > start |
| stop_conditions | 停止条件の一覧 | 空にできない |
| emergency_contact | 緊急連絡先 | 必須 |
| log_retention_days | 証跡の保存日数 | 正の整数 |

`match-evidence` は、範囲外のホストや期間外の実行を採点せずに除外し、終了コード 1 で知らせます。

## 3. 検証計画（`plan.csv`、`plan-candidates`）

| 列 | 内容 |
|---|---|
| scenario_id, step | シナリオと手順の順番（攻撃の連鎖を表す） |
| technique_id, procedure_id | 検証する技術と手順。組は一意 |
| reference | 手順の出典。例：`ctid-micro:ad_enum`、`atomic:<GUID>`、`internal:<ID>` |

`plan-candidates` は、業種別の重みの上位技術それぞれについて、CTID Adversary Emulation Library の中で該当する計画を一覧にします（`data/emulation/ctid_catalog.csv`）。分類は次の三つです。
- マイクロエミュレーション計画
- その業種のグループを模した攻撃者別計画
- その他の攻撃者別計画

一覧に載るのは計画の名前・URL・技術 ID だけで、計画の中身は含みません。

計画を `vdc --plan` に渡すと、技術ごとの分母が「計画した手順（と、計画外に実施した手順）」になります。未実施の手順は未検知として数えるので、易しい手順を一つだけ試して 100% になることはありません。

## 4. 証跡の照合（`match-evidence`）

| ファイル | 必須の列 | 任意の列 |
|---|---|---|
| runs.csv（エミュレーション側） | run_id, technique_id, procedure_id, host, started_at, ended_at | prevented, operator, tool |
| alerts.csv（SIEM/EDR のアラート） | event_id, rule_id, timestamp, host | technique_ids, uri, source |
| logs.csv（テレメトリ。任意） | event_id, timestamp, host | uri, source |

照合の規則：
- 同じホストで、時刻が「実行開始〜実行終了＋猶予（既定 300 秒）」の範囲にあるアラート・ログを、その実行に結びつける。
- アラートに ATT&CK の技術タグがある場合は、実行の技術と（親技術の単位で）一致するものだけを数える。
- 結果の各行には run_id、rule_id、event_id、evidence_uri、verifier が入る。`vdc` は既定で、証跡（event_id か evidence_uri）と確認者（verifier）のない検知・防御を数えない。
- どの実行にも結びつかなかったアラートは一覧で表示する（誤検知やノイズの手がかり）。

時刻はすべて UTC オフセット付きで受け取ります。異なるシステムの時刻を比べるため、オフセットのない時刻はエラーにします。

## 5. 指標の分離

| 指標 | 何が分かるか |
|---|---|
| 実施率 | 計画した手順のうち実施できた割合 |
| 検知率 D・防御率・ログ率 | 実施した手順に対する防御側の反応 |
| VDC（V の重みつき和） | 計画の範囲で、証跡つき・鮮度内で検知できた割合 |
| 鮮度の負債 | 検知はできていたが検証が失効した分（Σ w × 失効した検知の割合） |
| 回帰率 | 前回より検知率 D が下がった技術の割合（検知能力の低下） |
| 証跡のない検知 | 数えなかった自己申告の件数 |

鮮度の負債と回帰率を分けたので、「検知能力が落ちた」のか「検証が古くなっただけ」なのかを区別できます。

## 6. 未実装と今後

| 項目 | 状態 | 方針 |
|---|---|---|
| 攻撃の実行 | 対象外 | 承認済みの外部ツールに任せる |
| SIEM/EDR の API 連携 | 未実装 | 現在は CSV のエクスポートで受け取る。製品ごとの変換スクリプトを追加する |
| CALDERA の実行結果の取り込み | 未実装 | 実行記録を runs.csv に変換する取り込み処理 |
| シナリオの前後関係の評価 | 未実装 | 手順の連鎖のどこで検知できたか（最初の検知点）を指標にする |
| 対策の提案 | 未実装 | 検知漏れの技術に D3FEND の対策を対応づける |
