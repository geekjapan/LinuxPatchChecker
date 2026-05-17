# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

LinuxPatchChecker — a tool for checking patch status on Linux systems. The project is in early scaffolding; no source code exists yet.

## OpenSpec Workflow

This repo uses OpenSpec (`@fission-ai/openspec`) for spec-driven development.

- Config: `openspec/config.yaml`
- Specs: `openspec/specs/`
- Changes: `openspec/changes/` (active) and `openspec/changes/archive/` (completed)

Normal flow: `/opsx:propose` → `/opsx:apply` → `/opsx:sync` → `/opsx:archive`

Check active changes before starting new work:

```
openspec list --json
openspec status --change <name> --json
```

## Build / Test / Lint

```bash
pip install -e .          # パッケージをeditable modeでインストール
pytest                    # 全テスト実行
pytest tests/test_detector.py   # 単一テストファイルの実行
pytest -k "TestGrep"      # 特定のテストクラス/関数のみ実行
patch-checker --help      # CLIヘルプ
make build-check          # dist/patch-checker-check.pyz をビルド（stdlibのみ）
pip install shiv && make build-scan  # dist/patch-checker-scan.pyz をビルド（paramiko同梱）
make build                # 両方ビルド
make checksums            # dist/SHA256SUMS を生成
```

## Architecture

```
patch_checker/
  cli.py          # argparseサブコマンド（check/scan）、エントリポイント
  cve_db.py       # CVEEntry dataclass、cves.jsonのロード
  distro.py       # DistroInfo/KernelVersion、ディストリ判定・changelog解決
  detector.py     # CVEResult、grep_changelog/detect_permanent_fix/detect_all
  remediation.py  # disable_module/set_sysctl/apply_mitigation、権限チェック
  reporter.py     # format_text/format_json/exit_code
  ssh.py          # SSHScanner（paramiko）、scan_host/scan_hosts
  data/
    cves.json     # CVEメタデータ（影響バージョン範囲・暫定対策・恒久対策コマンド）
    cves.schema.md  # cves.json の全フィールド定義
```

**検知フロー**: `detect_all()` が各CVEに対してモジュール状態（lsmod）とchangelogグレップ（Ubuntu: gz、RHEL: rpm -q --changelog）を組み合わせて判定する。changelogが存在しない場合は `uname -r` バージョン比較にフォールバック。

各CVEの恒久対策判定には信頼性スコア（HIGH/MEDIUM/LOW）が付与される（`_compute_confidence()`）:
- HIGH: changelogグレップヒット
- MEDIUM: changelog存在・CVE未記載 かつ `version_comparison_reliable_for`（cves.yaml）に含まれるディストリ
- LOW: changelog不在 / ELSモード / 信頼マップ外のディストリ

LOW + FIXED は `MANUAL_CHECK_REQUIRED` に格上げされる（false negative防止）。ELS環境（RHEL 7/SLES 12/Ubuntu 16.04-18.04）は `distro.py:ELS_DISTROS` / `ELS_DISTRO_PREFIXES` で判定。

**SSH scanモード**: `ssh.py` がリモートホストで個別コマンド（uname/lsmod/sysctl/changelog grep）を実行し、結果をローカルで `detect_all()` に渡す。Python不要。

**CVEデータの更新**: `patch_checker/data/cves.json` のみ編集すればよい（コード変更不要）。フィールド定義は `patch_checker/data/cves.schema.md` 参照。
