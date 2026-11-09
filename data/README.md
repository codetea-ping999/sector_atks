# データの出典

| パス | 出典 | 利用条件 |
|---|---|---|
| `attack-v20.0/` | MITRE ATT&CK Enterprise v20.0 STIX（[mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data)、2026-10-13 版）から `build-weights` で生成 | [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/)。© The MITRE Corporation. ATT&CK® は The MITRE Corporation の登録商標 |
| `ctid/top_attack_prevalence.csv` | Center for Threat-Informed Defense, [Top ATT&CK Techniques](https://github.com/center-for-threat-informed-defense/top-attack-techniques) の `src/data/Techniques.json`（2025-05-28 のコミット）から `ctid-prevalence` で抽出 | Apache License 2.0。© The MITRE Corporation |
| `emulation/ctid_catalog.csv` | Center for Threat-Informed Defense, [Adversary Emulation Library](https://github.com/center-for-threat-informed-defense/adversary_emulation_library)（コミット 4467a6e、2025-05-28）から `scripts/build_emulation_catalog.py` で抽出。計画名・URL・模した ATT&CK グループ・文書中に出てくる技術 ID だけで、計画の中身は含まない | Apache License 2.0。© The MITRE Corporation |
| `group_sector_overrides.csv` | 本リポジトリで手動管理する修正 | — |

STIX 本体（約 55 MB）は含めていません。`python3 -m sector_atks fetch-attack --version 20.0` で取得できます。

## 業種判定の注意

`group_sectors.csv` は、グループ記述のうち標的を表す語（targeted, against, sectors など）より後ろで、帰属・動機の語句（attributed, sponsored, motivated など）より前の部分だけを対象に、業種のキーワードを探して付けています。手順は [docs/method.md](../docs/method.md) の 1 節にあります。

根拠は `evidence`（一致した語句）、`sentence`（その文の部分）、`source`（ATT&CK のページ）の各列で確認できます。誤りは `group_sector_overrides.csv` で直します。現在の上書きは 2 件で、抜き取り監査で見つかった誤りです（method.md の 4.1 節）。

業種を付けられなかったグループは `untagged_groups.csv`、業種ごとのデータの質（少数フラグ、ブートストラップ安定度）は `sector_summary.csv` にあります。
