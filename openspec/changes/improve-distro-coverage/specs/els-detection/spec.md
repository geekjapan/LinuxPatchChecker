## ADDED Requirements

### Requirement: ELS/LTSSモードの識別
システムはRHEL 7 ELS、SLES 12 SP5、Ubuntu 16.04/18.04 ESM、CentOS 7など、ベンダーが拡張サポート（ELS/ESM/LTSS）を提供する古い基底カーネルを使うディストリビューションをELSモードとして識別しなければならない（SHALL）。識別は`/etc/os-release`の`ID`と`VERSION_ID`の組み合わせで判定しなければならない（SHALL）。

#### Scenario: RHEL 7 のELSモード判定
- **WHEN** `/etc/os-release`の`ID=rhel`かつ`VERSION_ID="7"`
- **THEN** ELSモードフラグとして`True`が返される

#### Scenario: SLES 12 のELSモード判定
- **WHEN** `/etc/os-release`の`ID=sles`かつ`VERSION_ID`が`12`で始まる
- **THEN** ELSモードフラグとして`True`が返される

#### Scenario: Ubuntu ESMモード判定
- **WHEN** `/etc/os-release`の`ID=ubuntu`かつ`VERSION_ID="16.04"`または`"18.04"`
- **THEN** ELSモードフラグとして`True`が返される

#### Scenario: 通常サポート版の非ELS判定
- **WHEN** `/etc/os-release`の`ID=ubuntu`かつ`VERSION_ID="24.04"`
- **THEN** ELSモードフラグとして`False`が返される

### Requirement: ELSモードでのバックポート可能性考慮
システムはELSモードのディストリビューションで恒久対策を判定する際、changelogグレップでCVEが見つからない場合に`FIXED`ではなく`MANUAL_CHECK_REQUIRED`を返さなければならない（SHALL）。これはベンダーが脆弱なコードをバックポートしている可能性を排除できないためである。

#### Scenario: ELSモードでchangelogヒットなし
- **WHEN** RHEL 7 ELS環境でCVE-2026-31431を判定し、changelogグレップが空振り、かつカーネルバージョン（3.10）がNVD影響範囲外
- **THEN** 恒久対策ステータスとして`MANUAL_CHECK_REQUIRED`が返され、`backport_possible: true`の注記が付く

#### Scenario: ELSモードでchangelogヒットあり
- **WHEN** RHEL 7 ELS環境でCVE-2026-31431を判定し、changelogグレップが成功
- **THEN** 恒久対策ステータスとして`FIXED`が返される（ELSモードでも changelog ヒットは信頼可）
