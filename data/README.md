# データの出典

| パス | 出典 | 利用条件 |
|---|---|---|
| `attack-v20.0/` | MITRE ATT&CK Enterprise v20.0 STIX（[mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data)、2026-10-13 版）から `build-weights` で生成 | [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/)。© The MITRE Corporation. ATT&CK® は The MITRE Corporation の登録商標 |
| `ctid/top_attack_prevalence.csv` | Center for Threat-Informed Defense, [Top ATT&CK Techniques](https://github.com/center-for-threat-informed-defense/top-attack-techniques) の `src/data/Techniques.json`（2025-05-28 のコミット）から `ctid-prevalence` で抽出 | Apache License 2.0。© The MITRE Corporation |
| `group_sector_overrides.csv` | 本リポジトリで手動管理する修正 | — |

STIX 本体（約 55 MB）は含めていません。`python3 -m sector_atks fetch-attack --version 20.0` で取得できます。

## 業種判定の注意

`group_sectors.csv` は、グループ記述のうち「targeted」「against」「sectors」などの標的を表す語より後ろだけを対象に、業種のキーワードを探して付けています。これで「国家安全部に帰属」「軍の部隊」のような帰属の記述や、「financially motivated」のような動機の記述を業種と取り違えにくくしています。それでも誤判定と漏れは残るため、`evidence` 列の語句を見て、必要なら `group_sector_overrides.csv` で直してください。
