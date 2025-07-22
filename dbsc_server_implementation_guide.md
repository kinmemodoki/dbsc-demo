# DBSC (Device Bound Session Credentials) サーバサイド実装ガイド

## 概要

DBSC は、セッションクレデンシャルがデバイスから流出していないことをサーバが検証できる新しい API です。プライベートキーを使用し、TPM などのセキュアハードウェアや OS 提供 API を活用してマルウェアによる流出を防ぎます。

## サーバサイドの必要条件

### 基本要件

1. **HTTPS 必須**: すべてのエンドポイントは HTTPS で提供する必要があります（localhost を除く）
2. **セッション識別子の管理**: セッション識別子をレジストラブルドメイン内で一意に管理
3. **公開キーの永続化**: 各セッションに関連付けられた公開キーの保存
4. **チャレンジの管理**: セッションごとの現在のチャレンジを管理
5. **JWT 検証機能**: ES256 または RS256 での署名検証
6. **適切な CORS ポリシー**: クロスサイトリクエストの制御

### セキュリティ要件

- **タイミングサイドチャネル対策**: リフレッシュエンドポイントのレスポンス時間の一定化
- **CORS 制限**: リフレッシュエンドポイントでの `Access-Control-Allow-Credentials` の制限
- **X-Frame-Options**: リフレッシュエンドポイントの埋め込み防止
- **Sec-Secure-Session-Id ヘッダー検証**: リクエストがユーザエージェント発信であることの確認

## 必要なエンドポイント

### 1. セッション登録エンドポイント

**用途**: ブラウザが `Secure-Session-Registration` ヘッダーを受信した後に非同期でアクセス

**HTTPメソッド**: POST

**リクエストヘッダー**:
- `Secure-Session-Response`: DBSC Proof JWT
- `Sec-Secure-Session-Id`: セッション識別子（リフレッシュ時）
- `Authorization`: 認証情報（オプション）

**必要な処理**:

1. **JWT の検証**:
   ```
   - ヘッダー検証: typ="dbsc+jwt", alg="ES256" or "RS256"
   - ペイロード検証: aud, jti, iat, key クレーム
   - 署名検証: 公開キーによる署名の妥当性確認
   ```

2. **セッション設定の提供**:
   ```
   - 新しいセッション識別子の生成
   - 公開キーとセッション識別子の関連付け
   - セッション設定の JSON レスポンス
   ```

3. **レスポンス**:
   ```json
   {
     "session_identifier": "unique_session_id",
     "refresh_url": "/refresh",
     "continue": true,
     "scope": {
       "origin": "https://example.com",
       "include_site": false,
       "scope_specification": []
     },
     "credentials": [{
       "type": "cookie",
       "name": "session_cookie",
       "attributes": "Domain=example.com; Path=/; Secure; HttpOnly; SameSite=None"
     }],
     "allowed_refresh_initiators": ["example.com"]
   }
   ```

### 2. セッションリフレッシュエンドポイント

**用途**: 期限切れのバウンドクッキーを持つリクエストが発生したときにアクセス

**HTTPメソッド**: POST

**リクエストヘッダー**:
- `Secure-Session-Response`: DBSC Proof JWT
- `Sec-Secure-Session-Id`: セッション識別子

**必要な処理**:

1. **セッション識別子による検索**:
   ```
   - セッション識別子の妥当性確認
   - 関連する公開キーと最新チャレンジの取得
   ```

2. **DBSC Proof の検証**:
   ```
   - JWT ヘッダー・ペイロードの検証
   - チャレンジ署名の確認（ネットワーク遅延・競合状態を考慮）
   - sub クレームのセッション識別子確認
   ```

3. **新しいバウンドクッキーの発行**:
   ```
   - Set-Cookie ヘッダーによる新しいクッキーの設定
   - セッション設定の更新（オプション）
   ```

4. **エラーハンドリング**:
   - **403**: 古いチャレンジの場合、新しいチャレンジで再試行
   - **400-499**: セッション終了
   - **500-**: 一時的なエラー、バックオフ機構の実装推奨

### 3. チャレンジ配信

**レスポンスヘッダー**: `Secure-Session-Challenge`

**処理**:
```
Secure-Session-Challenge: "new_challenge_value";id="session_id"
```

- 将来の `Secure-Session-Response` で使用されるチャレンジの送信
- 403 ステータスでの即座のチャレンジ更新要求

## 実装上の重要な注意点

### 1. セキュリティ考慮事項

**タイミングサイドチャネル対策**:
```javascript
// リフレッシュエンドポイントでの一定時間レスポンス
const FIXED_RESPONSE_TIME = 100; // ms
const startTime = Date.now();

// 処理実行...

const elapsed = Date.now() - startTime;
const delay = Math.max(0, FIXED_RESPONSE_TIME - elapsed);
await new Promise(resolve => setTimeout(resolve, delay));
```

**CORS 設定**:
```javascript
// リフレッシュエンドポイントでは厳格な CORS
app.use('/refresh', (req, res, next) => {
  // Access-Control-Allow-Credentials を決して設定しない
  res.header('Access-Control-Allow-Origin', 'null');
  res.header('X-Frame-Options', 'DENY');
  next();
});
```

### 2. JWT 検証の実装例

```javascript
function verifyDBSCProof(jwt, expectedAud, expectedChallenge, publicKey) {
  const decoded = jwt.verify(jwt, publicKey);
  
  // 必須クレームの検証
  if (decoded.typ !== 'dbsc+jwt') throw new Error('Invalid typ');
  if (decoded.aud !== expectedAud) throw new Error('Invalid aud');
  if (decoded.jti !== expectedChallenge) throw new Error('Invalid challenge');
  if (!decoded.iat || Math.abs(Date.now()/1000 - decoded.iat) > 300) {
    throw new Error('Invalid iat');
  }
  
  return decoded;
}
```

### 3. セッション状態管理

```javascript
class DBSCSession {
  constructor() {
    this.sessionId = generateUniqueId();
    this.publicKey = null;
    this.currentChallenge = generateChallenge();
    this.lastActivity = Date.now();
    this.scope = null;
    this.credentials = [];
  }
  
  updateChallenge() {
    this.currentChallenge = generateChallenge();
    this.lastActivity = Date.now();
  }
  
  isExpired() {
    return Date.now() - this.lastActivity > SESSION_TIMEOUT;
  }
}
```

### 4. フェデレーション対応

プロバイダーキー共有時の検証:
```javascript
function validateFederatedSession(providerKey, providerId, providerUrl) {
  // .well-known エンドポイントの検証
  const wellKnownUrl = `${providerUrl}/.well-known/device-bound-sessions`;
  const wellKnownData = fetchWellKnown(wellKnownUrl);
  
  if (!wellKnownData.relying_origins.includes(currentOrigin)) {
    throw new Error('Origin not allowed for federation');
  }
  
  // 既存セッションの公開キー確認
  const providerSession = getSession(providerId);
  if (providerSession.publicKey !== providerKey) {
    throw new Error('Provider key mismatch');
  }
  
  return providerSession.keyPair;
}
```

### 5. .well-known エンドポイント

```javascript
app.get('/.well-known/device-bound-sessions', (req, res) => {
  res.json({
    "registering_origins": [
      "https://subdomain.example.com"
    ],
    "relying_origins": [
      "https://partner.example.com"
    ],
    "provider_origin": "https://idp.example.com" // RP の場合のみ
  });
});
```

### 6. エラーハンドリングとロギング

```javascript
function handleDBSCError(error, sessionId) {
  switch (error.type) {
    case 'INVALID_JWT':
      // セッション終了
      terminateSession(sessionId);
      return 400;
    case 'EXPIRED_CHALLENGE':
      // 新しいチャレンジで再試行
      return 403;
    case 'NETWORK_ERROR':
      // 一時的エラー
      return 503;
    default:
      console.error('DBSC Error:', error);
      return 500;
  }
}
```

### 7. パフォーマンス最適化

- **プロアクティブリフレッシュ**: クッキー期限前のリフレッシュ対応
- **同時リフレッシュ制限**: 同一セッションの重複リフレッシュ防止
- **TPM負荷軽減**: 過度なTPM操作の回避
- **キャッシュ戦略**: セッション情報の適切なキャッシュ

## まとめ

DBSC の実装には、セキュリティ、パフォーマンス、相互運用性の慎重な考慮が必要です。特にリフレッシュエンドポイントはセキュリティクリティカルな部分であり、適切な検証とエラーハンドリングが不可欠です。段階的な導入により、既存の認証スタックとの統合を図ることができます。