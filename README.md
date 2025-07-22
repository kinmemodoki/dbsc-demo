# DBSC Demo

Device Bound Session Credentials (DBSC) デモ Web アプリケーションです。  
このアプリケーションはChrome M139までの実装向けに作成されています。  
https://groups.google.com/a/chromium.org/g/dbsc-announce/c/YgET4jhSqQI

## 概要

このプロジェクトは DBSC を実装したデモアプリケーションで、以下の機能を提供します：

- DBSC による端末バインドセッション認証
- RESTful API エンドポイント

## 起動方法

### 前提条件

- Go 1.24 以上がインストールされていること

### 起動方法

```bash
go run main.go
```

アプリケーションは http://localhost:8080 で起動します。

## エンドポイント

- `GET /` - ホームページ
- `POST /login` - ログイン
- `POST /dbsc_register` - DBSC 登録
- `POST /dbsc_refresh` - DBSC リフレッシュ
- `/static/` - 静的ファイル配信

## 開発

### テスト実行
```bash
go test ./...
```

### フォーマット
```bash
go fmt ./...
```

### ビルド
```bash
go build
```
