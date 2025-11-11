# Workspace Manager API仕様書

`workspace-manager.js`は、ワークスペースのライフサイクル管理を担当するモジュールです。

## 概要

このモジュールは、Devcontainer CLIを使用してワークスペースコンテナを作成、管理します。各ワークスペースは独立したDockerコンテナとして実行され、code-serverを介してブラウザからアクセス可能なVS Code環境を提供します。

## 定数

### `WORKSPACES_BASE_DIR`
```javascript
const WORKSPACES_BASE_DIR = '/home/codespace/workspaces';
```
- ワークスペースディレクトリのベースパス
- 各ワークスペースは `${WORKSPACES_BASE_DIR}/${workspaceName}` に配置される
- codespaceユーザ（UID 1000）が所有

### `BUILD_LOGS_BASE_DIR`
```javascript
const BUILD_LOGS_BASE_DIR = '/home/codespace/buildlogs';
```
- ビルドログファイルのベースパス
- 各ログは `${BUILD_LOGS_BASE_DIR}/${workspaceName}.log` に保存される

### `NGINX_CONFIG_DIR`
```javascript
const NGINX_CONFIG_DIR = '/opt/nginx-config';
```
- Nginxの動的設定ファイルディレクトリ
- 各ワークスペースのリバースプロキシ設定を保存

## エクスポート関数

### `createWorkspace(username, workspaceName, repoUrl, envVars = {}, workspaceId = null)`

新しいワークスペースを作成します。

#### パラメータ

| パラメータ | 型 | 必須 | 説明 |
|-----------|-----|------|------|
| `username` | `string` | ✓ | GitHubユーザー名 |
| `workspaceName` | `string` | ✓ | ワークスペース名（英数字、ハイフン、アンダースコア） |
| `repoUrl` | `string` | ✓ | クローンするGitリポジトリのURL |
| `envVars` | `object` | - | 環境変数（現在未使用） |
| `workspaceId` | `number` | - | データベースのワークスペースID（ログ用） |

#### 戻り値

`Promise<Object>`

```javascript
{
  containerId: string,              // DockerコンテナID
  name: string,                     // ワークスペース名
  url: string,                      // ワークスペースURL（例: /username/workspaces/workspace-name）
  status: 'running',                // コンテナステータス
  devcontainerBuildStatus: string   // 'success' | 'failed' | 'no_devcontainer'
}
```

#### 処理フロー

1. **ディレクトリチェック**: 既存のワークスペースディレクトリがあれば削除
2. **ディレクトリ作成**: `/home/codespace/workspaces/${workspaceName}` を作成
3. **所有権設定**: `codespace:codespace` に変更
4. **リポジトリクローン**: `sudo -u codespace git clone` でクローン
5. **devcontainer検出**: `.devcontainer/devcontainer.json` の存在チェック
6. **コンテナビルド**: `buildWithDevcontainerCLI()` を呼び出し

#### エラー

- ディレクトリが削除できない場合
- git cloneに失敗した場合
- devcontainerのビルドに失敗した場合

---

### `buildWorkspace(username, workspaceName, envVars = {}, workspaceId = null)`

既存のワークスペースを再ビルドします。

#### パラメータ

| パラメータ | 型 | 必須 | 説明 |
|-----------|-----|------|------|
| `username` | `string` | ✓ | GitHubユーザー名 |
| `workspaceName` | `string` | ✓ | ワークスペース名 |
| `envVars` | `object` | - | 環境変数（現在未使用） |
| `workspaceId` | `number` | - | データベースのワークスペースID（ログ用） |

#### 戻り値

`Promise<Object>` - `createWorkspace()`と同じ形式

#### 処理フロー

1. **ディレクトリ確認**: ワークスペースディレクトリの存在チェック
2. **devcontainer検出**: `.devcontainer/devcontainer.json` の存在チェック
3. **コンテナビルド**: `buildWithDevcontainerCLI()` を呼び出し

#### エラー

- ワークスペースディレクトリが存在しない場合
- devcontainerのビルドに失敗した場合

---

### `deleteWorkspace(containerId)`

ワークスペースとそのリソースを削除します。

#### パラメータ

| パラメータ | 型 | 必須 | 説明 |
|-----------|-----|------|------|
| `containerId` | `string` | ✓ | DockerコンテナID |

#### 戻り値

`Promise<void>`

#### 処理フロー

1. **コンテナ情報取得**: ラベルからusernameとworkspaceNameを取得
2. **コンテナ停止**: 実行中の場合は停止
3. **コンテナ削除**: Dockerコンテナを削除
4. **Nginx設定削除**: リバースプロキシ設定ファイルを削除
5. **Nginxリロード**: 設定を反映
6. **ディレクトリ削除**: ワークスペースディレクトリを削除（リトライあり）

#### エラー

- コンテナが存在しない場合: エラーをスローし、`server.js`が`cleanupWorkspaceFiles()`を呼び出す
- ディレクトリ削除に失敗した場合: 警告ログを出力するが、エラーはスローしない

---

### `startWorkspace(containerId)`

停止中のワークスペースを起動します。

#### パラメータ

| パラメータ | 型 | 必須 | 説明 |
|-----------|-----|------|------|
| `containerId` | `string` | ✓ | DockerコンテナID |

#### 戻り値

`Promise<void>`

#### 処理フロー

1. **コンテナ起動**: `docker.start()`でコンテナを起動
2. **待機**: 2秒間待機
3. **code-server起動**: コンテナ内でcode-serverを起動
4. **ポート確認**: code-serverがポート8080で起動するまで待機（最大30秒）

#### エラー

- コンテナの起動に失敗した場合
- code-serverの起動に失敗した場合

---

### `stopWorkspace(containerId)`

実行中のワークスペースを停止します。

#### パラメータ

| パラメータ | 型 | 必須 | 説明 |
|-----------|-----|------|------|
| `containerId` | `string` | ✓ | DockerコンテナID |

#### 戻り値

`Promise<void>`

#### 処理フロー

1. **code-server停止**: `pkill -f 'code-server'` で停止を試みる
2. **コンテナ停止**: `docker.stop()`でコンテナを停止

#### エラー

- コンテナの停止に失敗した場合

---

### `getBuildLogPath(username, workspaceName)`

ビルドログファイルのパスを取得します。

#### パラメータ

| パラメータ | 型 | 必須 | 説明 |
|-----------|-----|------|------|
| `username` | `string` | ✓ | GitHubユーザー名（現在未使用） |
| `workspaceName` | `string` | ✓ | ワークスペース名 |

#### 戻り値

`string` - ビルドログファイルの絶対パス

例: `/home/codespace/buildlogs/my-workspace.log`

---

### `cleanupWorkspaceFiles(username, workspaceName)`

コンテナが存在しない場合のワークスペースファイルのクリーンアップ。

#### パラメータ

| パラメータ | 型 | 必須 | 説明 |
|-----------|-----|------|------|
| `username` | `string` | ✓ | GitHubユーザー名 |
| `workspaceName` | `string` | ✓ | ワークスペース名 |

#### 戻り値

`Promise<void>`

#### 処理フロー

1. **Nginx設定削除**: リバースプロキシ設定ファイルを削除
2. **Nginxリロード**: 設定を反映
3. **待機**: 2秒間待機（マウント解放待ち）
4. **ディレクトリ削除**: ワークスペースディレクトリを削除（リトライあり）

#### エラー

- Nginxリロードに失敗した場合: 警告ログを出力するが続行
- ディレクトリ削除に失敗した場合: 警告ログを出力するが続行

---

## 内部関数（非公開）

### `buildWithDevcontainerCLI()`

Devcontainer CLIを使用してコンテナをビルドし、起動します。

**主な処理**:
- `devcontainer up --skip-post-create` の実行
- デフォルトイメージへのフォールバック（エラー時）
- ネットワーク接続（`pseudo-codespaces_pseudo-codespaces`）
- bridgeネットワークからの切断
- UID 1000ユーザの確認・作成
- code-serverのインストール（root）と起動（UID 1000）
- Nginx設定の更新

### `ensureUID1000User()`

コンテナ内にUID 1000のユーザが存在することを保証します。

**動作**:
- 現在のユーザを確認
- rootの場合: UID 1000ユーザを確認・作成
- 非rootの場合: UIDを1000に変更

### `removeWorkspaceDirectory()`

ワークスペースディレクトリを削除します（最大3回リトライ）。

**方法**:
1. 直接削除: `rm -rf`
2. Dockerコンテナ経由: `docker run --rm -v ... ubuntu:22.04 rm -rf`

### `updateNginxConfig()`

Nginxのリバースプロキシ設定を作成・更新します。

**生成される設定**:
```nginx
location /{username}/workspaces/{workspaceName}/ {
    proxy_pass http://{containerIP}:8080/;
    # WebSocket、ヘッダー設定など
}
```

## 設定とカスタマイズ

### devcontainer.jsonのサポート

- **存在する場合**: リポジトリの`.devcontainer/devcontainer.json`を使用
- **存在しない場合**: デフォルト設定で一時的なdevcontainer.jsonを作成
  ```json
  {
    "name": "{workspaceName}",
    "image": "mcr.microsoft.com/devcontainers/universal:2-linux",
    "workspaceFolder": "/workspaces/{workspaceName}",
    "workspaceMount": "source={workspaceDir},target=/workspaces/{workspaceName},type=bind"
  }
  ```

### 重要な制限事項

1. **postCreateCommandのスキップ**: `--skip-post-create`オプションにより、devcontainer.jsonの`postCreateCommand`、`postStartCommand`、`postAttachCommand`は実行されません
   - **理由**: これらのコマンドがワークスペースファイルを変更する可能性があるため

2. **ユーザー権限**: すべてのワークスペース操作はcodespaceユーザ（UID 1000）で実行されます

3. **ネットワーク**: カスタムDockerネットワーク`pseudo-codespaces_pseudo-codespaces`を使用

## ログとデバッグ

### ログの種類

1. **アプリケーションログ**: Pinoロガーを使用（構造化JSON）
2. **ビルドログ**: `/home/codespace/buildlogs/{workspaceName}.log`
3. **code-serverログ**: コンテナ内の`/tmp/code-server.log`

### ログレベル

```javascript
const wsLogger = createWorkspaceLogger(username, workspaceName);
const buildLogger = createActionLogger(username, workspaceName, 'action');
const containerLogger = createContainerLogger(username, workspaceName, containerId);
```

## トラブルシューティング

### コンテナが起動しない

1. ビルドログを確認: `cat /home/codespace/buildlogs/{workspace-name}.log`
2. Dockerログを確認: `docker logs {container-id}`
3. devcontainer.jsonの構文エラーをチェック

### ネットワークエラー

- bridgeネットワークの切断に失敗する場合がありますが、通常は無視して続行します
- カスタムネットワークへの接続が重要です

### ファイルが見えない

- `workspaceMount`と`workspaceFolder`が正しく設定されているか確認
- マウントパーミッション（codespace:codespace）を確認

## セキュリティ考慮事項

1. **ユーザー分離**: 各ワークスペースは独立したコンテナで実行
2. **UID管理**: UID 1000で統一してファイル権限を管理
3. **ネットワーク分離**: カスタムネットワークを使用
4. **認証なし**: code-serverは`--auth none`で起動（Nginxで認証済み）

## パフォーマンス最適化

1. **リトライロジック**: ディレクトリ削除は最大3回リトライ
2. **非同期処理**: Promiseを使用した非同期処理
3. **ログバッファ**: 10MBのバッファでビルド出力を処理
4. **待機時間**: 適切な待機時間を設定（ネットワーク安定化、code-server起動など）

## 今後の改善案

- [ ] 環境変数のサポート（現在は未実装）
- [ ] ワークスペーステンプレート機能
- [ ] カスタムイメージのサポート
- [ ] リソース制限の設定（CPU、メモリ）
- [ ] ワークスペースのバックアップ・リストア機能
