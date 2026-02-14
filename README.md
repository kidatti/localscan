# localscan

A fast CLI tool for discovering devices on your local network. No root privileges required.

> Japanese documentation is available [below](#localscan-日本語).

## Features

- Auto-detection of network interfaces
- Multi-method scanning (ICMP / TCP / UDP / ARP)
- Reverse DNS hostname resolution
- MAC address vendor identification
- Open port detection per host
- Multiple output formats (table / JSON / CSV)
- File output support
- Diff detection against previous scan
- Cross-platform (Linux / macOS / Windows)

## Installation

Download the binary for your platform from the [Releases](https://github.com/kidatti/localscan/releases) page.

### macOS (Apple Silicon)

```bash
curl -LO https://github.com/kidatti/localscan/releases/latest/download/localscan-darwin-arm64.tar.gz
tar xzf localscan-darwin-arm64.tar.gz
xattr -d com.apple.quarantine localscan
sudo mv localscan /usr/local/bin/
```

### macOS (Intel)

```bash
curl -LO https://github.com/kidatti/localscan/releases/latest/download/localscan-darwin-amd64.tar.gz
tar xzf localscan-darwin-amd64.tar.gz
xattr -d com.apple.quarantine localscan
sudo mv localscan /usr/local/bin/
```

### Linux (x86_64)

```bash
curl -LO https://github.com/kidatti/localscan/releases/latest/download/localscan-linux-amd64.tar.gz
tar xzf localscan-linux-amd64.tar.gz
sudo mv localscan /usr/local/bin/
```

### Linux (ARM64)

```bash
curl -LO https://github.com/kidatti/localscan/releases/latest/download/localscan-linux-arm64.tar.gz
tar xzf localscan-linux-arm64.tar.gz
sudo mv localscan /usr/local/bin/
```

### Windows

[Releases](https://github.com/kidatti/localscan/releases) から `localscan-windows-amd64.zip` をダウンロードし、展開して PATH の通ったフォルダに配置してください。

### Build from source

```bash
git clone https://github.com/kidatti/localscan.git
cd localscan
make build
```

## Usage

### Basic

```bash
# Auto-detect network interface
./localscan

# Specify interface
./localscan -interface en0

# Adjust timeout and workers
./localscan -timeout 1000 -workers 50
```

### Output Formats

```bash
# Table output (default)
./localscan

# JSON output
./localscan -format json

# CSV output
./localscan -format csv

# Write to file
./localscan -format json -o results.json
./localscan -format csv -o results.csv
```

### Diff Detection

Compare the current scan with the previous one. Results are saved to `~/.localscan/last.json`.

```bash
# First scan — all hosts marked as NEW
./localscan -diff

# Second scan — shows NEW / GONE status
./localscan -diff
```

- `NEW` — Host not seen in previous scan
- `GONE` — Host was in previous scan but not found now
- (blank) — Host present in both scans

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-interface` | (auto) | Network interface name |
| `-timeout` | 500 | Connection timeout in ms |
| `-workers` | 100 | Concurrent scan workers |
| `-format` | table | Output format: table, json, csv |
| `-o` | (stdout) | Output file path |
| `-diff` | false | Compare with previous scan |

## Output Example

### Table

```
Scanning 192.168.1.0/24 (254 hosts)...
[+] Found: 192.168.1.1 [ICMP]
[+] Found: 192.168.1.10 [TCP]
[========================================] 254/254 Complete

+------+--------------+------------------+-------------------+---------+--------+---------+
|  #   | IP Address   | Hostname         | MAC Address       | Vendor  | Method | Ports   |
+------+--------------+------------------+-------------------+---------+--------+---------+
|   1  | 192.168.1.1  | router.local     | AA:BB:CC:DD:EE:FF | ASUS    | ICMP   | 53,80   |
|   2  | 192.168.1.10 | pc.local         | 11:22:33:44:55:66 | Apple   | TCP    | 22,5900 |
+------+--------------+------------------+-------------------+---------+--------+---------+
Found 2 devices in 3.2s
```

### JSON

```json
[
  {
    "ip": "192.168.1.1",
    "hostname": "router.local",
    "mac": "AA:BB:CC:DD:EE:FF",
    "vendor": "ASUS",
    "method": "ICMP",
    "open_ports": [53, 80]
  }
]
```

### Diff Table

```
+------+--------------+----------+-------------------+---------+--------+-------+--------+
|  #   | IP Address   | Hostname | MAC Address       | Vendor  | Method | Ports | Status |
+------+--------------+----------+-------------------+---------+--------+-------+--------+
|   1  | 192.168.1.1  | router   | AA:BB:CC:DD:EE:FF | ASUS    | ICMP   | 53,80 |        |
|   2  | 192.168.1.20 | newpc    | 11:22:33:44:55:66 | Apple   | TCP    | 22    | NEW    |
|   3  | 192.168.1.10 | oldpc    | 77:88:99:AA:BB:CC | Dell    | ICMP   | -     | GONE   |
+------+--------------+----------+-------------------+---------+--------+-------+--------+
```

## How It Works

1. **ICMP Ping** — Uses system `ping` command to check host liveness
2. **TCP Connect** — Probes 30+ common ports (SSH, HTTP, SMB, etc.) and records open ports
3. **UDP Probe** — Sends protocol-specific packets (mDNS, SSDP, NetBIOS, SNMP)
4. **ARP Table** — Discovers additional hosts from ARP cache populated by probes

## Cross Compilation

```bash
make all
```

Binaries are generated in `dist/`:

- `localscan-linux-amd64`
- `localscan-linux-arm64`
- `localscan-darwin-amd64`
- `localscan-darwin-arm64`
- `localscan-windows-amd64.exe`

---

# localscan (日本語)

ローカルネットワーク上のデバイスを高速に検出するCLIツールです。root権限不要で動作します。

## 機能

- ネットワークインターフェースの自動検出
- マルチメソッドスキャン（ICMP / TCP / UDP / ARP）
- ホスト名の逆引き解決
- MACアドレスからのベンダー識別
- ホストごとの開放ポート検出
- 複数の出力形式に対応（テーブル / JSON / CSV）
- ファイル出力対応
- 前回スキャンとの差分検出
- クロスプラットフォーム対応（Linux / macOS / Windows）

## インストール

[Releases](https://github.com/kidatti/localscan/releases) ページからお使いの環境に合ったバイナリをダウンロードしてください。

### macOS (Apple Silicon)

```bash
curl -LO https://github.com/kidatti/localscan/releases/latest/download/localscan-darwin-arm64.tar.gz
tar xzf localscan-darwin-arm64.tar.gz
xattr -d com.apple.quarantine localscan
sudo mv localscan /usr/local/bin/
```

### macOS (Intel)

```bash
curl -LO https://github.com/kidatti/localscan/releases/latest/download/localscan-darwin-amd64.tar.gz
tar xzf localscan-darwin-amd64.tar.gz
xattr -d com.apple.quarantine localscan
sudo mv localscan /usr/local/bin/
```

### Linux (x86_64)

```bash
curl -LO https://github.com/kidatti/localscan/releases/latest/download/localscan-linux-amd64.tar.gz
tar xzf localscan-linux-amd64.tar.gz
sudo mv localscan /usr/local/bin/
```

### Linux (ARM64)

```bash
curl -LO https://github.com/kidatti/localscan/releases/latest/download/localscan-linux-arm64.tar.gz
tar xzf localscan-linux-arm64.tar.gz
sudo mv localscan /usr/local/bin/
```

### Windows

[Releases](https://github.com/kidatti/localscan/releases) から `localscan-windows-amd64.zip` をダウンロードし、展開して PATH の通ったフォルダに配置してください。

### ソースからビルド

```bash
git clone https://github.com/kidatti/localscan.git
cd localscan
make build
```

## 使い方

### 基本

```bash
# ネットワークインターフェースを自動検出
./localscan

# インターフェースを指定
./localscan -interface en0

# タイムアウトとワーカー数を調整
./localscan -timeout 1000 -workers 50
```

### 出力形式

```bash
# テーブル出力（デフォルト）
./localscan

# JSON出力
./localscan -format json

# CSV出力
./localscan -format csv

# ファイルに出力
./localscan -format json -o results.json
./localscan -format csv -o results.csv
```

### 差分検出

前回のスキャン結果と比較します。結果は `~/.localscan/last.json` に保存されます。

```bash
# 初回スキャン：全ホストが NEW
./localscan -diff

# 2回目：NEW / GONE のステータスを表示
./localscan -diff
```

- `NEW` — 前回にはなかったホスト
- `GONE` — 前回はあったが今回は見つからなかったホスト
- （空欄） — 両方のスキャンに存在するホスト

### オプション

| フラグ | デフォルト | 説明 |
|------|---------|-------------|
| `-interface` | (自動) | 使用するネットワークインターフェース名 |
| `-timeout` | 500 | 接続タイムアウト（ミリ秒） |
| `-workers` | 100 | 並行スキャンワーカー数 |
| `-format` | table | 出力形式: table, json, csv |
| `-o` | (stdout) | 出力ファイルパス |
| `-diff` | false | 前回スキャンとの差分表示 |

## 仕組み

1. **ICMP Ping** — システムの `ping` コマンドでホストの生存確認
2. **TCP Connect** — 主要ポート（SSH, HTTP, SMBなど30以上）への接続試行、開放ポートを記録
3. **UDP Probe** — mDNS, SSDP, NetBIOS, SNMP等のプロトコル固有パケット送信
4. **ARP Table** — 上記プローブで生成されたARPキャッシュから追加ホストを検出

## クロスコンパイル

```bash
make all
```

以下のバイナリが `dist/` に生成されます:

- `localscan-linux-amd64`
- `localscan-linux-arm64`
- `localscan-darwin-amd64`
- `localscan-darwin-arm64`
- `localscan-windows-amd64.exe`
