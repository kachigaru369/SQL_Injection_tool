# SQLI Multi-Test Tool

**Advanced SQL Injection Testing & Automation Framework**
高度なSQLインジェクションテスト＆自動化フレームワーク

---

## 📌 Overview / 概要

**English**
This tool is a professional, interactive Python framework designed for **multi-method SQL Injection testing** in web applications. It supports **URL parameters, POST fields, cookies, and HTTP headers**, and provides both **manual and automated testing capabilities** for:

* Blind SQL Injection (boolean-based, error-based, time-based)
* UNION-based injection & column count detection
* Database fingerprinting and data extraction
* Interactive payload building with placeholders
* Automated form discovery and parameter selection
* Optional integration with Playwright for browser-based verification

Payload dictionaries are modular and can be loaded from external files for **customized attack scenarios**.

**日本語**
このツールは、Webアプリケーションにおける**多手法SQLインジェクションテスト**のために設計された、プロフェッショナルかつ対話型のPythonフレームワークです。**URLパラメータ、POSTフィールド、Cookie、HTTPヘッダ**に対応し、以下の機能を手動・自動で実行できます：

* ブラインドSQLインジェクション（真偽ベース、エラーベース、タイムベース）
* UNIONベースのインジェクションとカラム数検出
* データベースの特定と情報抽出
* プレースホルダ対応のインタラクティブなペイロード構築
* 自動フォーム検出とパラメータ選択
* Playwrightとの連携によるブラウザ検証（オプション）

ペイロード辞書はモジュール化されており、外部ファイルから読み込むことで**攻撃シナリオをカスタマイズ可能**です。

---

## 🚀 Features / 特徴

**English**

* ✅ Multi-target support: URL, POST, Cookie, Header
* ✅ Blind SQLi automation with dynamic placeholders
* ✅ UNION-based enumeration helpers
* ✅ Automatic form parsing (BeautifulSoup)
* ✅ Database fingerprint payload sets (`first_test.py`)
* ✅ Flexible payload expansion & selection system
* ✅ Built-in error pattern scanning
* ✅ Playwright integration for in-browser review

**日本語**

* ✅ マルチターゲット対応：URL、POST、Cookie、Header
* ✅ 動的プレースホルダを用いたブラインドSQLi自動化
* ✅ UNIONベースの列挙補助機能
* ✅ BeautifulSoupによる自動フォーム解析
* ✅ データベース識別用ペイロードセット（`first_test.py`）
* ✅ 柔軟なペイロード展開・選択システム
* ✅ エラーパターン検出機能内蔵
* ✅ ブラウザ確認用Playwright連携

---

## 📂 Project Structure / プロジェクト構成

```text
SQL_Injection_tool/
├── SQLI_multi_test.py       # Main application / メインアプリケーション
├── first_test.py            # Example payload dictionaries / ペイロード辞書例
├── payloads/                # Custom payload files / カスタムペイロード
└── README.md                # Documentation / ドキュメント
```

---

## ⚙️ Requirements / 必要条件

**English**

* Python 3.8+
* `requests`
* `beautifulsoup4` (for form parsing)
* `playwright` (optional, for browser integration)

Install dependencies:

```bash
pip install requests beautifulsoup4 playwright
playwright install
```

**日本語**

* Python 3.8以上
* `requests`
* `beautifulsoup4`（フォーム解析用）
* `playwright`（オプション、ブラウザ連携用）

依存関係のインストール:

```bash
pip install requests beautifulsoup4 playwright
playwright install
```

---

## 🧩 Installation / インストール

```bash
git clone https://github.com/kachigaru369/SQL_Injection_tool
cd SQL_Injection_tool
```

---

## 🛠 Usage / 使用方法

**English**

1. Run the main script:

```bash
python3 SQLI_multi_test.py
```

2. Select the target URL and injection point (URL, POST, Cookie, Header).
3. Choose or load payloads (supports `{placeholders}`).
4. Execute blind mode, UNION helper, data extraction, or error scanning.

**日本語**

1. メインスクリプトを実行:

```bash
python3 SQLI_multi_test.py
```

2. ターゲットURLと注入ポイント（URL、POST、Cookie、Header）を選択。
3. ペイロードを選択または読み込み（`{placeholder}`対応）。
4. ブラインドモード、UNION補助、データ抽出、エラースキャンを実行。

---

## 📜 Example Payload Dictionary (`first_test.py`) / ペイロード辞書例

**English**
`first_test.py` contains ready-to-use SQLi payload sets for different databases (Oracle, MySQL, MSSQL, PostgreSQL, SQLite) and scenarios (error-based, row filtering, blind extraction).

**日本語**
`first_test.py`には、各種データベース（Oracle、MySQL、MSSQL、PostgreSQL、SQLite）やシナリオ（エラーベース、行フィルタリング、ブラインド抽出）に対応したSQLiペイロードセットが含まれています。

---

## ⚠️ Legal Disclaimer / 免責事項

**English**
This tool is intended **only** for authorized security testing on systems you own or have explicit permission to test. Misuse of this tool may violate laws and result in severe consequences. The author assumes **no liability** for any damage caused.

**日本語**
本ツールは、**自分が所有するシステム**または**明確な許可を得たシステム**に対するセキュリティテストのみを目的としています。不正使用は法律に違反し、重大な結果を招く可能性があります。作者は、本ツールの使用によって生じた損害について**一切の責任を負いません**。
