# プロジェクト基本情報

このプロジェクトは Go で書かれた DBSC (Device Bound Session Credentials) デモ Web アプリケーションです。
- Gorilla Mux をルーターとして使用
- JWT を使用した認証機能
- ポート 8080 で起動

# 共通コマンド

- `go build`: プロジェクトのビルド実行
- `go run main.go`: アプリケーションの起動
- `go test ./...`: 全テストの実行
- `go test -v ./dbsc`: dbsc パッケージの単体テスト実行
- `go mod tidy`: 依存関係の整理
- `go fmt ./...`: コードフォーマット

# ワークフロー

- 全テストではなく単体テストを優先して実行
- コード変更後は `go fmt` でフォーマットを実行
- ビルド前に `go mod tidy` で依存関係を確認

# エンドポイント

- `/`: ホームページ
- `/login`: ログイン (POST)
- `/dbsc_register`: DBSC 登録 (POST)
- `/dbsc_refresh`: DBSC リフレッシュ (POST)
- `/static/`: 静的ファイル配信

# important-instruction-reminders
Do what has been asked; nothing more, nothing less.
NEVER create files unless they're absolutely necessary for achieving your goal.
ALWAYS prefer editing an existing file to creating a new one.
NEVER proactively create documentation files (*.md) or README files. Only create documentation files if explicitly requested by the User.
