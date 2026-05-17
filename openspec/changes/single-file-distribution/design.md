## Context

v1の配布形態は `pip install -e .` 開発モードのみ。本番Linuxサーバーは多くの場合インターネット未接続でpip経由のインストールができない。手動転送ではファイル数が多いほど運用ミスとコストが増える。

ツール本体は2つのモードを持つ:
- **モードA（ローカル検知・適用）**: target host上で実行。stdlibのみで完結可能（PyYAMLを排除すれば）
- **モードB（SSH一括スキャン）**: 管理ホスト上で実行。paramikoが必要

target hostは制約が厳しい（オフライン、最小依存）、管理ホストは比較的緩い（pip available可、複数アーキ対応不要）。この非対称性を活かして2つの.pyzを別ビルドする。

## Goals / Non-Goals

**Goals:**
- target hostへの配布を「1ファイル + Python 3.8+」だけで完結させる
- 管理ホスト向けにparamiko同梱の.pyzも別途提供する
- `wget`/`curl`によるサイト配布と`scp`による手動転送の両方をサポート
- ビルド・配布をCIで自動化

**Non-Goals:**
- target hostでのSSHスキャン実行（モードBは管理ホスト専用）
- Python不要なバイナリ配布（PyInstaller等、v3で検討）
- aarch64以外のアーキテクチャ（v2初版はx86_64 Linux優先）
- 自動アップデート機構

## Decisions

### D1: target host向けはピュアPython zipapp（stdlib のみ）

**理由**: target hostにはPython 3が標準で入っている（Ubuntu/Debian/RHEL/SLES全て）。stdlibのみで動作すれば追加のwheel配布が不要で、ピュアPython .pyzはアーキ非依存になる。zipappはPython標準ツール（`python -m zipapp`）でビルドできる。

**代替案**: shivでpyyaml同梱 → サイズ膨張・アーキ依存。pyyamlを排除すればstdlibで完結する。

### D2: 管理ホスト向けはshiv（paramiko同梱）

**理由**: paramikoはcryptography（C拡張）依存のため、wheelをバンドルする必要がある。shivはwheelを含む.pyzをビルドできる標準的なツール。管理ホストはx86_64 Linuxを想定（必要に応じてaarch64を追加ビルド）。

**代替案**: PEX → 機能はほぼ同等だがshivの方がシンプル。

### D3: CVEデータは `cves.yaml` から `cves.json` に変更

**理由**: PyYAMLはピュアPythonでも動作するがインストール対象。stdlib の `json` モジュールで読めるJSONに変換すればPyYAML依存を完全排除できる。YAMLのコメント機能は失うが、JSONはツールが充実している（jq等）。

**代替案**: PyYAMLをvendoring（コピーして同梱）→ ライセンス管理・更新追跡が面倒。

### D4: 配布チャネルはGitHub Releases

**理由**: タグpush→CI→Releaseで自動化が容易。`wget`/`curl`の対象URLが安定（`https://github.com/<org>/<repo>/releases/download/<tag>/<file>`）。プライベートリポジトリでも `gh release download` で取得可能。

**代替案**: 自前のWebサーバ → 別途運用が必要。

### D5: ビルドツールは Makefile + Python標準ツール

```makefile
.PHONY: build build-check build-scan

build: build-check build-scan

build-check:
	python3 -m zipapp patch_checker -p '/usr/bin/env python3' -o dist/patch-checker-check.pyz -m patch_checker.cli:main

build-scan:
	shiv -c patch-checker -o dist/patch-checker-scan.pyz .
```

**理由**: Makefileは Linux/macOS で動作するシンプルなビルドツール。`python -m zipapp` は stdlib に含まれる。`shiv` のみ追加開発依存。

### D6: 実行方法とエントリポイント

```bash
# pip install版（既存）
patch-checker check

# zipapp版（新規）
python3 patch-checker-check.pyz check
python3 patch-checker-scan.pyz scan host1 host2
```

zipappの `-m patch_checker.cli:main` で `cli.main` をエントリにする。これで`pip install` 版と同じ動作になる。

### D7: GitHub Actions release workflow

```yaml
on:
  push:
    tags: ['v*']
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: pip install shiv
      - run: make build
      - uses: softprops/action-gh-release@v2
        with:
          files: |
            dist/patch-checker-check.pyz
            dist/patch-checker-scan.pyz
```

### D8: バージョン情報の埋め込み

`patch_checker/__init__.py` に `__version__` を定義し、ビルド時にREADMEの説明と共にバージョンが分かるようにする。`--version` フラグを追加する（任意、初版は省略可）。

## Risks / Trade-offs

- **.pyz のオーバーヘッド** → 起動時に~100ms程度遅くなる。検知用途では問題なし
- **shiv の wheel キャッシュ場所** → デフォルトで `~/.shiv` に展開する。本番hostで予期せぬ書き込みは避けたい → shivビルド時 `--site-packages-only` などで対策、または管理ホストのみで使う旨明記
- **JSON化によるコメント喪失** → cves.json の隣に `cves.schema.md` を置いて判断基準を文書化
- **CIなしでビルドできない** → 開発者でも `make build` 一発でローカルビルド可能にする
- **`scp` 配布時のチェックサム** → SHA256をReleasesに併載し、転送後の検証手順をREADMEに記載

## Migration Plan

1. `cves.yaml` を `cves.json` に変換（同等内容、コメントは別ファイルへ）
2. `cve_db.py` を `yaml.safe_load` から `json.load` に切り替え
3. `pyproject.toml` から PyYAML 依存を削除（または `[project.optional-dependencies]` に移動）
4. `scripts/build.sh` と `Makefile` を追加
5. ローカルで `make build` → `dist/*.pyz` が生成されることを確認
6. 既存テスト全パス確認
7. GitHub Actions workflow追加
8. v0.2.0タグでリリース

ロールバック: `cves.json` を YAMLに戻し、依存を復元するだけ。コードの本質的変更は最小。

## Open Questions

- aarch64 Linux向けの.pyzをいつ追加するか → 初版はx86_64のみ。要望があれば追加
- shivの `--reproducible` オプションを使うか → 再現可能ビルドはセキュリティ的に望ましい。初版から有効化を推奨
- `--version` フラグの追加 → タスクとしては小さいが、初版に含めると配布物のバージョン確認が容易。含める方針
