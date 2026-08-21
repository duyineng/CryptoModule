## 0 背景准备

内部 CA 生成私钥 ca.key 和 证书文件 ca.crt（内含 CA 公钥）。

密钥管理服务端 KeyManagementServer（KMS）同时有 ca.crt，server.key，server.crt（由 CA 签发，内含 server 公钥）

网点终端电脑同时也有 ca.crt，terminal.key，terminal.crt（由 CA 签发，内含 terminal 公钥）

密钥管理客户端 KeyManagementClient（KMC）启动后，向 KMS 发起 mTLS 握手。

在 mTLS 握手过程中，KMS 向 KMC 发送 server.crt 和 server.key 生成的 TLS 握手签名。KMC 使用 ca.crt 验证 server.crt ，再使用 `server.crt` 中的公钥验证握手签名。

接着，KMC 向 KMS 发送 `terminal.crt` 和 `terminal.key` 生成的 TLS 握手签名。KMS 使用 `ca.crt` 验证 `terminal.crt`，再使用 `terminal.crt` 中的公钥验证握手签名。

双方验证成功后，协商 TLS 会话密钥并建立 mTLS 加密通道。

## 1 KMC 和 KMS 

KMC 调用 `connect()` 与 KMS 建立 TCP 连接。TCP 连接建立后，双方在该连接上执行 mTLS 握手。握手成功后，KMC 和 KMS 之间建立经过双向身份认证的 TLS 加密通道。后续的工作密钥申请和自动轮换，都通过这个安全通道完成。

### 1.1 通信协议

KMC 和 KMS 使用 HTTP 协议通信，HTTP 请求和响应都通过已经建立的 mTLS 加密通道传输。KMC 使用以 OpenSSL 为 TLS 后端的 libcurl 发起 HTTPS 请求；业务接口的请求体和响应体采用 Protobuf 二进制编码。

### 1.2 工作密钥申请

KMC 调用以下接口申请工作密钥：

```http
POST /api/v1/work-keys HTTP/1.1
Host: kms.example.com
Content-Type: application/x-protobuf
X-Request-Id: 8e09c9c5-91e7-45f5-a172-68b3778c4ac1
```

`X-Request-Id` 用于标识一次逻辑申请，同一次申请因超时而重试时，KMC 必须复用相同的 `X-Request-Id`

请求体对应的 Protobuf 消息：

```proto
message ApplyWorkKeyRequest {
  string algorithm = 1;
  uint32 key_length = 2;
}
```

KMS 收到申请后依次执行：

1. 从当前 TLS 会话的客户端证书中获取终端身份。
2. 根据 KMS 策略校验该终端是否有权申请指定算法和长度的工作密钥。
3. 查询该终端是否已经拥有未过期的工作密钥：如果存在，则复用该密钥；如果不存在、已过期，则进入下一步生成新密钥。
4. 仅在没有可复用密钥时，生成新的工作密钥，并生成唯一的 `keyId`。
5. 安全保存新生成的密钥材料，并记录密钥元数据：
   - **密钥材料**是工作密钥本身的二进制字节，例如 AES-256 的 32 字节随机值。密钥材料不得以明文写入普通数据库。应使用 KMS 主密钥加密后保存。
   - **密钥元数据**是描述和管理该密钥的信息，不包含密钥明文，至少包括 `keyId`、`algorithm`、`keyLength`、`status`、`createdAt`、`expiresAt`，以及密钥所属的终端。
6. 将申请结果组装成 HTTP 响应，通过当前 mTLS 通道返回给 KMC。

响应体对应的 Protobuf 消息：

```proto
message WorkKeyResponse {
  string request_id = 1;
  string key_id = 2;
  string algorithm = 3;
  uint32 key_length = 4;
  string status = 5;
  string created_at = 6;
  string expires_at = 7;
  int64 expires_at_unix = 8;
  bytes key_material = 9;
}
```

`key_material` 是原始二进制工作密钥。Protobuf 的 `bytes` 字段可以直接承载二进制数据，不需要 Base64 编码。该字段通过 mTLS 通道返回，TLS 会保证其传输过程中的机密性和完整性。KMC 收到后必须立即写入受保护内存，不得写入日志或普通磁盘文件。

### 1.3 密钥自动轮换

KMC 固定在密钥 expiresAt 前 2 小时发起轮换请求

```http
POST /api/v1/work-keys/wk_outlet001_000001/rotations HTTP/1.1
Host: kms.example.com
Content-Type: application/x-protobuf
X-Request-Id: 4b7c9a7e-...
```

请求体对应的 Protobuf 消息：

```proto
message RotateWorkKeyRequest {
  string algorithm = 1;
  uint32 key_length = 2;
}
```

KMS 收到 HTTP 请求消息后：

- 校验终端是否有权轮换；
- 生成新的工作密钥；
- 为新工作密钥生成全新的 `keyId`；
- 安全保存新密钥；
- 将旧 `keyId` 标记为过渡状态，过渡期结束后停用并清理；
- 返回新 `keyId` 对应的密钥和元数据。

响应体仍使用 `WorkKeyResponse`，其中 `key_id` 为新生成的密钥标识，例如 `wk_outlet001_000002`。

## 2 SDK 和 KMC 

SDK 从始至终不接触密钥，使用 Windows 命名管道与 KMC 通信。命名管道消息采用“4 字节大端长度 + Protobuf 二进制消息”的帧格式。

### 2.1 SDK 请求 KMC

SDK 请求对应 `SdkRequest` Protobuf 消息，其中操作通过 `oneof` 表示加密或解密。KMC 使用 OpenSSL EVP 接口完成 AES-256-GCM 加解密，再通过同一命名管道返回 `SdkResponse`。

```proto
message SdkRequest {
  string request_id = 1;
  oneof op {
    EncryptOp encrypt = 2;
    DecryptOp decrypt = 3;
  }
}

message EncryptOp {
  bytes plaintext = 1;
}

message DecryptOp {
  string key_id = 1;
  bytes nonce = 2;
  bytes ciphertext = 3;
  bytes auth_tag = 4;
}
```

KMC 响应包含 `request_id`、处理状态、`key_id`、`nonce`、密文和认证标签；解密成功时包含明文。所有二进制字段均使用 Protobuf `bytes` 直接传输。
```

## 3 关于 Windows 服务

C++ 程序需要使用 Windows Service API，如 `StartServiceCtrlDispatcher(...)`，然后编译生成 `KMC.exe`，最后在 PowerShell 中使用 `sc.exe create` 命令注册服务，并配置为自动启动。这样 KMC 服务就会在每次 Windows 开机之后自动运行。当前开发版本是普通控制台程序，暂未加入 Windows Service API。

## 4 实现细节

KMC 使用 libcurl + OpenSSL 实现基于 mTLS 的 HTTPS 通信，使用 Protobuf 编码业务消息，并使用 OpenSSL EVP 实现 AES-256-GCM 加解密。KMS 使用 Python HTTPS 服务和 SQLite 保存密钥数据，工作密钥经 KMS 主密钥加密后落库。

