## Why

v1リリース後のレビューで、恒久対策判定の精度に3つのギャップが判明した: (1) Ubuntu形式の `uname -r`（例: `5.15.0-73-generic`）がパッケージバージョンと無関係なため version 比較が false negative を返す、(2) RHEL 7 ELS / SLES 12 SP5 などのELS/LTSS環境はNVDの mainline 影響範囲外だがベンダーバックポートで脆弱な場合があり、現フォールバックは誤って FIXED と判定する、(3) WSL2 や自前ビルドカーネルは changelog 不在のためフォールバックに依存するが、ユーザーへの信頼性表示が不十分である。これらは特に長期サポート版で運用される本番環境でリスクとなる。

## What Changes

- Ubuntu/Debian環境で `dpkg-query -W -f '${Version}' linux-image-$(uname -r)` から完全パッケージバージョンを取得する仕組みを追加
- 各CVEに `version_comparison_reliable_for` リストを追加し、信頼できないディストリではフォールバックを `MANUAL_CHECK_REQUIRED` に格上げ
- RHEL 7 ELS / SLES 12 SP5 など ELS/LTSS モードのディストリを識別し、changelog 空振り時に `MANUAL_CHECK_REQUIRED` を返す
- `changelog_source.type == 'none'` の WSL2 / 汎用環境向けに、出力に「ベンダーアドバイザリの手動確認を推奨」警告を追加
- テキスト/JSON出力に「検知信頼性: HIGH/MEDIUM/LOW」フィールドを追加
- **BREAKING**: 一部の以前 FIXED と判定されていた古いLTSSカーネル・Ubuntuカーネルが `MANUAL_CHECK_REQUIRED` に変わる（安全側への変更）

## Capabilities

### New Capabilities

- `els-detection`: RHEL 7 ELS / SLES 12 SP5 などのELS/LTSSモード識別と「バックポート可能性あり」フラグの付与

### Modified Capabilities

- `distro-detection`: Ubuntu/Debian用パッケージバージョン取得（`dpkg-query`）の追加、ELSモードの識別フィールド追加
- `cve-database`: `version_comparison_reliable_for` フィールドの追加
- `vulnerability-detection`: 信頼性スコア（HIGH/MEDIUM/LOW）の算出、信頼性が低い場合の `MANUAL_CHECK_REQUIRED` への格上げ
- `reporting`: 検知信頼性の出力追加、WSL2/汎用環境向け警告メッセージの追加

## Impact

- **コード**: `patch_checker/distro.py`（dpkg-query追加、ELS判定追加）、`patch_checker/detector.py`（信頼性スコア・MANUAL_CHECK_REQUIRED格上げ）、`patch_checker/reporter.py`（信頼性表示）、`patch_checker/data/cves.yaml`（5件のCVEすべてに `version_comparison_reliable_for` 追加）
- **テスト**: 既存テストの期待値更新（Ubuntu/ELS環境のMANUAL_CHECK_REQUIRED格上げに対応）、新規テスト追加
- **CLI互換性**: コマンドライン引数は変更なし。出力フォーマットに「信頼性」項目が追加されるためJSON消費側に影響あり
- **外部依存**: なし（dpkg-queryはDebian系標準コマンド）
