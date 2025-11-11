# Pseudo CodeSpaces on Sakura Cloud

さくらのクラウド上でGitHub CodeSpaces風のクラウド開発環境を提供するサービスです。

## 概要

このプロジェクトは、さくらのクラウド上でGitHub CodeSpacesに似た機能を提供します：

- GitHub OAuthによる認証（PKCE & stateパラメータによるセキュリティ強化）
- ユーザーごとのワークスペース管理
- GitリポジトリからのワークスペースのClone
- code-serverによるブラウザベースのVS Code環境
- devcontainer.jsonのサポート
- Let's EncryptによるSSL/TLS証明書の自動取得
- Nginx + Node.js + SQLite3によるWebサービス

## アーキテクチャ

```
┌─────────────────────────────────────────────────┐
│           Sakura Cloud Server (Ubuntu)          │
│                                                  │
│  ┌────────────┐  ┌──────────────────────────┐   │
│  │   Nginx    │  │  Pseudo CodeSpaces App   │   │
│  │  (Reverse  │──│  (Node.js + Express)     │   │
│  │   Proxy)   │  │  - GitHub OAuth          │   │
│  │  + SSL/TLS │  │  - Workspace Management  │   │
│  └────────────┘  │  - SQLite3 DB            │   │
│                  └──────────────────────────┘   │
│                                                  │
│  ┌──────────────────────────────────────────┐   │
│  │     Workspace Containers                 │   │
│  │  ┌────────────┐  ┌────────────┐          │   │
│  │  │code-server │  │code-server │  ...     │   │
│  │  │ (VS Code)  │  │ (VS Code)  │          │   │
│  │  └────────────┘  └────────────┘          │   │
│  └──────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
```

## 前提条件

### ローカル環境（開発用）

- GitHub CodeSpaces または VS Code + Dev Container拡張
- GitHub アカウント

### さくらのクラウド

- さくらのクラウドアカウント
- APIキー（トークン + シークレット）
- ドメイン（事前にDNS設定が可能なもの）

### GitHub OAuth App

GitHubで新しいOAuth Appを作成してください：

1. GitHub Settings → Developer settings → OAuth Apps → New OAuth App
2. 以下の情報を設定：
   - Application name: `Pseudo CodeSpaces`
   - Homepage URL: `https://your-domain.com`
   - Authorization callback URL: `https://your-domain.com/auth/github/callback`
3. Client IDとClient Secretを控えておく

## セットアップ手順

### 1. リポジトリをClone

```bash
git clone https://github.com/your-username/pseudo-code-spaces-sakura.git
cd pseudo-code-spaces-sakura
```

### 2. GitHub CodeSpacesまたはDev Containerで開く

このリポジトリには `.devcontainer/devcontainer.json` が含まれているので、自動的に必要なツールがインストールされます。

### 3. 環境変数の設定

#### GitHub CodeSpacesの場合

リポジトリの Settings → Secrets and variables → Codespaces で以下を追加：

**重要**: GitHub CodeSpacesのSecretsは自動的に大文字に変換されるため、以下の大文字の変数名で登録してください。

```
TF_VAR_SAKURA_TOKEN=<さくらのクラウドのトークン>
TF_VAR_SAKURA_SECRET=<さくらのクラウドのシークレット>
TF_VAR_SSH_PUBLIC_KEY=<~/.ssh/id_rsa.pubの内容>
TF_VAR_DOMAIN=<あなたのドメイン>
TF_VAR_GITHUB_CLIENT_ID=<GitHub OAuth AppのClient ID>
TF_VAR_GITHUB_CLIENT_SECRET=<GitHub OAuth AppのClient Secret>
DEPLOYER_EMAIL=<SSL証明書の期限切れ警告メールを受け取るメールアドレス>
```

Dev Containerが起動すると、これらは自動的にTerraformが認識できる形式に変換されます。

📘 **詳細なガイド**: [docs/CODESPACES_SECRETS.md](docs/CODESPACES_SECRETS.md)を参照してください。

#### ローカル環境の場合

```bash
# Sakura Cloud API
export TF_VAR_sakura_token="your-sakura-token"
export TF_VAR_sakura_secret="your-sakura-secret"

# SSH公開鍵（~/.ssh/id_rsa.pubの内容）
export TF_VAR_ssh_public_key="ssh-rsa AAAA..."

# ドメイン
export TF_VAR_domain="your-domain.com"

# GitHub OAuth
export TF_VAR_github_client_id="your-github-client-id"
export TF_VAR_github_client_secret="your-github-client-secret"

# SSL証明書の期限切れ警告メールアドレス（オプション）
# 未設定の場合は admin@your-domain.com が使用されます
export DEPLOYER_EMAIL="your-email@example.com"
```

### 4. Terraformでインフラをデプロイ

```bash
cd terraform

# 初期化
terraform init

# プラン確認
terraform plan

# 適用
terraform apply
```

デプロイが完了すると、サーバーのIPアドレスが表示されます。

### 5. DNSレコードの設定

取得したIPアドレスをドメインのAレコードに設定してください。

```
A   your-domain.com   →   IPアドレス
```

DNSの伝播を待ちます（通常数分〜数時間）。

### 6. Ansibleでサーバーを構築

```bash
cd ../ansible

# インベントリファイルを編集
# terraformの出力からIPアドレスをコピー
nano inventory.ini

# 必要なAnsibleコレクションをインストール
ansible-galaxy collection install -r requirements.yml

# Playbookを実行
ANSIBLE_CONFIG=ansible.cfg ansible-playbook -i inventory.ini playbook.yml
```

Ansibleが以下を自動的に実行します：

- Dockerのインストール
- Let's EncryptからSSL証明書の取得
- アプリケーションのデプロイ
- Nginxの設定
- コンテナの起動

### 7. サービスへアクセス

ブラウザで `https://your-domain.com` にアクセスしてください。

## 使用方法

### ログイン

1. `https://your-domain.com` にアクセス
2. 「GitHubでログイン」ボタンをクリック
3. GitHubで認証・認可

### ワークスペースの作成

1. ダッシュボードで「+ 新規ワークスペース」をクリック
2. 以下を入力：
   - **ワークスペース名**: 英数字、ハイフン、アンダースコアのみ
   - **Gitリポジトリ URL**: Clone元のリポジトリURL
   - **環境変数**: JSON形式（オプション）
3. 「作成」をクリック

ワークスペースが作成されると、以下が自動実行されます：

- `/home/codespace/workspaces/{workspace-name}` にgit clone（codespaceユーザ、UID 1000で実行）
- `.devcontainer/devcontainer.json` の検出と適用（存在する場合）
- `devcontainer up --skip-post-create` によるコンテナビルドと起動
- UID 1000ユーザの確認・作成
- code-serverのインストール（rootユーザ）と起動（UID 1000ユーザ）
- Nginxリバースプロキシの設定追加

### ワークスペースへのアクセス

1. ダッシュボードのワークスペース一覧で「開く」をクリック
2. 新しいタブでcode-serverが開きます
3. ブラウザ上でVS Codeを使用して開発可能

### ワークスペースの管理

- **起動**: 停止中のワークスペースを起動
- **停止**: 実行中のワークスペースを停止（データは保持）
- **削除**: ワークスペースとコンテナを完全削除

## プロジェクト構成

```
.
├── .devcontainer/
│   ├── devcontainer.json       # Dev Container設定
│   └── post-create.sh          # セットアップスクリプト
├── terraform/
│   ├── main.tf                 # Terraformメイン設定
│   ├── variables.tf            # 変数定義
│   ├── server.tf               # サーバーリソース
│   ├── outputs.tf              # 出力定義
│   └── cloud-init.yaml         # Cloud-init設定
├── ansible/
│   ├── playbook.yml            # メインPlaybook
│   ├── ansible.cfg             # Ansible設定
│   ├── inventory.ini           # インベントリ
│   ├── requirements.yml        # Ansibleコレクション要件
│   └── templates/
│       └── env.j2              # 環境変数テンプレート
├── app/
│   ├── server.js               # Expressサーバー
│   ├── database.js             # SQLiteデータベース
│   ├── workspace-manager.js    # ワークスペース管理
│   ├── package.json            # Node.js依存関係
│   └── public/
│       ├── index.html          # ランディングページ
│       └── dashboard.html      # ダッシュボード
├── docker/
│   ├── docker-compose.yml      # Docker Compose設定
│   └── app/
│       └── Dockerfile          # アプリDockerfile
└── nginx/
    ├── nginx.conf              # Nginxメイン設定
    └── conf.d/                 # 動的設定ディレクトリ
```

## セキュリティ機能

- **GitHub OAuth認証**: PKCE & stateパラメータによるCSRF対策
- **SSL/TLS**: Let's Encryptによる自動証明書取得
- **セキュアなセッション**: httpOnly, secure cookieの使用
- **Rate Limiting**: API呼び出しの制限
- **Helmet.js**: セキュリティヘッダーの設定
- **パケットフィルタ**: さくらのクラウドのファイアウォール設定

## トラブルシューティング

### 🚨 緊急: サーバーにログインできない（SSH/Webコンソール両方）

**症状**: `terraform destroy` → `deploy.sh` で再構築後、以下の問題が発生：
- SSH接続がタイムアウト
- pingが応答しない
- Webコンソールで「Login incorrect」

**原因**: 以前の設定で`lifecycle.ignore_changes`がパスワード設定を無効化していた

**解決策**: 修正済みの設定で完全再デプロイ

```bash
# 最新のコードを取得（修正済み）
git pull

# 完全再デプロイスクリプトを実行
./scripts/full-redeploy.sh
```

これにより：
- ✅ `lifecycle.ignore_changes`が削除され、パスワードが適用される
- ✅ cloud-initで`chpasswd`モジュールを使用してパスワードを設定
- ✅ ICMP（ping）がパケットフィルタに追加される
- ✅ サーバー起動待機時間が追加される

📘 **詳細**: [docs/SSH_CONNECTION_TROUBLESHOOTING.md](docs/SSH_CONNECTION_TROUBLESHOOTING.md)

### Terraformエラー: Ubuntuイメージが見つからない

```
Error: Your query returned no results.
```

**原因**: さくらのクラウドで利用可能なUbuntuイメージ名が異なる

**解決策**:
1. さくらのクラウドのコントロールパネルでパブリックアーカイブを確認
2. Ubuntu 24.04の正確な名前をコピー
3. `terraform/server.tf`の`names`を更新

📘 **詳細**: [docs/SAKURA_UBUNTU_IMAGE.md](docs/SAKURA_UBUNTU_IMAGE.md) を参照

### Terraformエラー: APIキーが無効

```
Error: API authentication failed
```

**解決策**:
- `TF_VAR_SAKURA_TOKEN`（CodeSpaces）または`TF_VAR_sakura_token`（ローカル）が正しく設定されているか確認
- さくらのクラウドのコントロールパネルでAPIキーが有効か確認

### Ansibleエラー: インベントリが見つからない

```
[WARNING]: No inventory was parsed, only implicit localhost is available
```

**解決策**:
- `ansible/inventory.ini`にサーバーIPアドレスが設定されているか確認
- 明示的にインベントリを指定: `ANSIBLE_CONFIG=ansible.cfg ansible-playbook -i inventory.ini playbook.yml`

📘 **詳細**: [docs/ANSIBLE_TROUBLESHOOTING.md](docs/ANSIBLE_TROUBLESHOOTING.md) を参照

### SSL証明書の取得に失敗する

- DNSレコードが正しく設定されているか確認
- ドメインがIPアドレスに解決されるか確認: `nslookup your-domain.com`
- ポート80, 443が開いているか確認

### ワークスペースが起動しない

- サーバーのログを確認: `ssh ubuntu@your-server "docker logs pseudo-codespaces-app"`
- Docker Daemonが実行中か確認: `ssh ubuntu@your-server "systemctl status docker"`

### Nginxリロードが失敗する

- Nginx設定の構文チェック: `docker exec nginx nginx -t`
- Nginxコンテナのログ確認: `docker logs nginx`

## メンテナンス

### SSL証明書の自動更新

SSL証明書は**毎日午前3時に自動的にチェック・更新**されます。Let's Encryptは証明書の有効期限が30日未満の場合に自動更新します。

更新処理には以下が含まれます：
- Certbotによる証明書の更新チェック
- 更新された証明書のアプリディレクトリへのコピー
- Nginxコンテナのリロード
- 更新ログの記録 (`/var/log/certbot-renewal.log`)

手動で証明書を更新する場合：

```bash
ssh ubuntu@your-server
sudo /usr/local/bin/renew-cert.sh your-domain.com
```

または、certbotコマンドを直接実行：

```bash
ssh ubuntu@your-server
sudo certbot renew
sudo cp /etc/letsencrypt/live/your-domain.com/*.pem /opt/pseudo-codespaces/ssl/
docker exec nginx nginx -s reload
```

### 証明書更新の確認

更新ログを確認：

```bash
ssh ubuntu@your-server
sudo tail -f /var/log/certbot-renewal.log
```

証明書の有効期限を確認：

```bash
ssh ubuntu@your-server
sudo certbot certificates
```

### バックアップ

定期的にSQLiteデータベースをバックアップしてください：

```bash
ssh ubuntu@your-server
cp /opt/pseudo-codespaces/app/data/database.db ~/backup/
```

### アップデート

```bash
cd /opt/pseudo-codespaces
git pull
docker compose down
docker compose up -d --build
```

## ライセンス

MIT License

## 貢献

プルリクエストを歓迎します！

## サポート

問題が発生した場合は、GitHubのIssuesで報告してください。
