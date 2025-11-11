# GitHub CodeSpaces環境変数設定ガイド

## 重要な注意事項

**GitHub CodeSpacesのSecretsは自動的に大文字に変換されます。**

そのため、変数名を正しく設定することが重要です。

## 設定手順

### 1. リポジトリのSecretsページにアクセス

1. GitHubリポジトリのページを開く
2. Settings タブをクリック
3. 左サイドバーの "Secrets and variables" → "Codespaces" を選択

### 2. Secretsを追加

"New repository secret" ボタンをクリックして、以下の変数を**大文字**で追加してください：

| Secret名（大文字で入力） | 説明 | 例 |
|---|---|---|
| `TF_VAR_SAKURA_TOKEN` | さくらのクラウドAPIトークン | `abc123def456...` |
| `TF_VAR_SAKURA_SECRET` | さくらのクラウドAPIシークレット | `xyz789uvw012...` |
| `TF_VAR_SSH_PUBLIC_KEY` | SSH公開鍵の内容 | `ssh-rsa AAAAB3Nza...` |
| `TF_VAR_DOMAIN` | 使用するドメイン名 | `example.com` |
| `TF_VAR_GITHUB_CLIENT_ID` | GitHub OAuth AppのClient ID | `Iv1.abc123...` |
| `TF_VAR_GITHUB_CLIENT_SECRET` | GitHub OAuth AppのClient Secret | `abc123def456...` |
| `DEPLOYER_EMAIL` | SSL証明書の通知用メールアドレス（オプション） | `admin@example.com` |

**注意**: `DEPLOYER_EMAIL`は省略可能です。設定しない場合は `admin@{ドメイン名}` が自動的に使用されます。

### 3. SSH公開鍵の取得方法

#### ローカルマシンで既に鍵を持っている場合

```bash
# 公開鍵の内容を表示
cat ~/.ssh/id_rsa.pub
```

出力された内容全体をコピーして `TF_VAR_SSH_PUBLIC_KEY` に貼り付けてください。

#### 鍵を持っていない場合

```bash
# 新しいSSH鍵ペアを生成
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"

# 公開鍵の内容を表示
cat ~/.ssh/id_rsa.pub
```

### 4. 動作の仕組み

CodeSpacesで変数を設定すると：

1. **設定**: `TF_VAR_SAKURA_TOKEN` として大文字で登録
2. **CodeSpaces内**: 環境変数 `TF_VAR_SAKURA_TOKEN` として利用可能
3. **Dev Container起動時**: `.devcontainer/devcontainer.json` が自動変換
4. **コンテナ内**: `TF_VAR_sakura_token` として利用可能（Terraformが認識）

この変換は `.devcontainer/devcontainer.json` の `remoteEnv` セクションで行われています：

```json
"remoteEnv": {
  "TF_VAR_sakura_token": "${localEnv:TF_VAR_SAKURA_TOKEN}${localEnv:TF_VAR_sakura_token}",
  ...
}
```

この設定により、大文字（CodeSpaces）でも小文字混じり（ローカル）でも動作します。

### `DEPLOYER_EMAIL` について

`DEPLOYER_EMAIL` はLet's Encryptで SSL/TLS証明書を取得する際に使用されるメールアドレスです：

- **用途**: 証明書の有効期限が近づいた際の警告メールを受信
- **必須**: いいえ（オプション）
- **デフォルト値**: 未設定の場合は `admin@{TF_VAR_DOMAIN}` が自動的に使用されます
- **推奨**: 実際に受信可能なメールアドレスを設定することを推奨します

例:
```bash
DEPLOYER_EMAIL=your-email@example.com
```

この設定により、証明書の有効期限が30日未満になった際に、Let's Encryptから更新リマインダーが送信されます。証明書は自動更新されますが、万が一更新に失敗した場合に通知を受け取ることができます。

## 設定確認

CodeSpacesまたはDev Containerを起動後、ターミナルで以下を実行して確認：

```bash
# セットアップチェックスクリプトを実行
./scripts/check-setup.sh
```

すべての環境変数が正しく設定されていれば、緑色のチェックマークが表示されます。

## よくある質問

### Q: 小文字混じりで設定してしまった

A: 問題ありません。GitHub CodeSpacesが自動的に大文字に変換するため、結果的に大文字になります。ただし、一貫性のため最初から大文字で設定することをお勧めします。

### Q: ローカルのDev Containerで使いたい

A: ローカル環境では `.env` ファイルを作成するか、シェルで環境変数をエクスポートしてください。小文字混じりで設定してください：

```bash
export TF_VAR_sakura_token="your-token"
export TF_VAR_sakura_secret="your-secret"
export DEPLOYER_EMAIL="your-email@example.com"
# ...
```

### Q: 既に小文字混じりで設定済み

A: CodeSpacesを削除して再作成し、Secretsを大文字で設定し直してください。

## トラブルシューティング

### 環境変数が見つからないエラー

```bash
# 環境変数が正しく設定されているか確認
env | grep TF_VAR
```

期待される出力:
```
TF_VAR_sakura_token=...
TF_VAR_sakura_secret=...
TF_VAR_ssh_public_key=...
TF_VAR_domain=...
TF_VAR_github_client_id=...
TF_VAR_github_client_secret=...
```

### Dev Containerが起動しない

1. CodeSpacesを削除
2. Secretsが大文字で設定されているか確認
3. CodeSpacesを再作成

## 参考リンク

- [GitHub CodeSpaces Secrets](https://docs.github.com/en/codespaces/managing-your-codespaces/managing-encrypted-secrets-for-your-codespaces)
- [Dev Container環境変数](https://containers.dev/implementors/json_reference/#general-properties)
