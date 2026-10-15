# Android 与 iOS 手机自动化

App 抓包页面提供统一的截图、元素树、点击、输入、滑动、启动 App 与返回桌面入口。平台分别使用 Android ADB 和 iOS WebDriverAgent（WDA）。HTTPS 抓包使用同一工作区的 MITM 代理与 CA。

## Android

1. 安装 Android Platform Tools，连接 USB，在手机上开启 USB 调试并授权电脑。
2. 在 App 抓包页选择 Android 和设备，开启主动操作，点击开始抓包。
3. 点击推送 CA，在手机上确认安装。自己的测试 App 需要信任测试 CA，应用的正式版可能不信任用户 CA。
4. 刷新截图，勾选点击截图操作手机，或者读取元素按文字/资源 ID 定位。

USB 抓包使用 `adb reverse`，手机代理 `127.0.0.1` 会转发到电脑。Wi-Fi 模式填写电脑局域网 IP，不能填手机自己的 loopback。Android 原生 ADB 输入仅支持可打印 ASCII，中文仍需输入法或其他自动化后端。

## iOS 自动准备

1. 连接并解锁 iPhone，信任电脑。在 App 抓包页选择 iOS，点击“检测 iPhone 环境”。单台手机会自动选择，多台时明确选择 USB 设备。
2. 开启主动操作，点击“自动准备并连接”。后台检查 go-ios；支持的架构缺少工具时，从官方 v1.3.2 发布资产下载并验证固定 SHA-256。也可通过 `CAPX_IOS_TOOL` 指定本地匹配架构的 go-ios。
3. WDA 已安装时，填写其 bundle ID 即可启动。需要安装时选择有效签名的 IPA；需要重新签名时，提供本地开发证书 P12 和允许调试、包含这台设备的开发描述文件。未提供 IPA、但已提供完整开发身份时，调用 go-ios 下载、签名并安装默认 WDA。
4. P12 口令在电脑启动 capx 前设置为 `CAPX_WDA_P12_PASSWORD`，不要发送到聊天或写进项目。后台在内存中解锁后创建私有临时签名副本，任务结束删除；原口令不进入 HTTP 请求、子进程命令行或公开日志。P12 证书必须与描述文件一致且未过期。
5. 后台为 iOS 17+ 检查/启动通信隧道，准备开发者镜像，启动 XCTest 和 USB 转发，再连接 WDA。系统要求开发者模式、管理员权限或手机上的 UI 自动化授权时，页面显示具体阶段及失败原因，由操作者完成相应系统确认。
6. 就绪后可截图、点击、输入中文、滑动、启动 App 和返回桌面。iOS 微信 bundle ID 为 `com.tencent.xin`；iOS 没有 Android 通用返回键，使用页面返回按钮或手势。

可在后台启动环境中配置 `CAPX_WDA_IPA`、`CAPX_WDA_P12`、`CAPX_WDA_PROFILE`、`CAPX_WDA_BUNDLE_ID`，避免反复填写路径。签名、IPA 与配对资料保存在本机，不随公开源码发布。程序本身不创建 Apple 账号，也不自动获取属于其他人的开发身份。

已有外部 WDA 可继续使用“连接 WDA”入口。自动准备不会接管占用端口的未知 WDA，也不会在多台 USB 设备中猜测目标。“停止自有任务”仅取消本实例的任务和辅助进程；断开手动连接不会停止外部 XCTest。

HTTPS 抓包另行启用 Wi-Fi 入口：填写手机 IP 白名单，在 iPhone Wi-Fi 设置填电脑 IP 和端口，安装当前工作区 CA，并在“设置 → 通用 → 关于本机 → 证书信任设置”开启完全信任。WDA 控制授权与 CA 信任是不同系统设置。

WDA 截图使用像素，操作坐标使用 UIKit points，页面会自动换算。REST 截图附带 points 尺寸，MCP 同时返回图片和坐标说明。屏幕旋转后刷新截图；失效会话不会自动重试点击或输入。

工具接口依据 [go-ios v1.3.2](https://github.com/danielpaulus/go-ios/tree/v1.3.2) 与 [Appium WebDriverAgent](https://github.com/appium/WebDriverAgent)。官方资产自动下载目前覆盖已核对的 Windows/Linux/Intel macOS 架构；其他架构使用 `CAPX_IOS_TOOL` 指向原生构建。

## MCP 示例

自动准备可调用 `capx_mobile_ios_prepare`，随后用 `capx_mobile_ios_prepare_status` 查询阶段；`capx_mobile_ios_setup` 检查 USB、工具与签名配置。

先开启后台的主动操作开关，并在 MCP 配置设置 `CAPX_MCP_ACTIVE=1`。查询已有流量和截图不需要开启主动操作。

```json
{"tool":"capx_mobile_ios_connect","arguments":{"body":{"endpoint":"http://127.0.0.1:8100"}}}
{"tool":"capx_mobile_screenshot","arguments":{"platform":"ios","serial":"ios-wda"}}
{"tool":"capx_mobile_tap","arguments":{"platform":"ios","serial":"ios-wda","body":{"text":"搜索"}}}
{"tool":"capx_mobile_input","arguments":{"platform":"ios","serial":"ios-wda","body":{"value":"小米"}}}
{"tool":"capx_mobile_home","arguments":{"platform":"ios","serial":"ios-wda"}}
```

上面的 JSON 表示工具名称和参数，供支持 MCP 的 AI 客户端调用。iOS 截图结果同时返回图片和 points 尺寸；AI 根据图片像素宽高按比例换算后传入 x/y，或者使用元素文字和 accessibility name（`resource_id`）定位。Android 省略 `platform` 或填 `android`，并传入对应的 ADB serial。

分析失败接口示例：`capx_list_http` 参数 `{"status":"400-599","limit":100}`；然后用 `capx_get_http` 读取具体请求，对比参数与响应。查询历史不会操作手机。

## 已捕获接口的业务解密

在 App 抓包页的“接口业务密文解密”填写 HTTP 交易 ID、请求/响应及 JSON Pointer（例如 `/data/ciphertext`），配置 AES 模式、密文编码和密钥/IV。密钥可仅用于本次请求，或引用后台 `CAPX_APP_` 前缀的密钥环境变量。结果单独显示，原始记录保持不变。

REST/MCP `capx_http_decrypt` 还支持 DES、3DES、RC4 和 RSA；字段为 `algorithm`、`mode`、`side`、`json_pointer`、`input_enc`、`key_env`、`iv_env`、`private_key_env` 等。输入先处理 HTTP 传输编码与支持的压缩，再提取密文字段。已截断正文会被拒绝。AES-GCM 验证认证标签；CBC、CTR 等模式的运算成功不等于消息经过认证。

这条流程需要有效业务密钥；HTTPS 代理证书不能替代业务密钥，也不能把散列值还原成原始密码。

## 小程序与解密

小程序调试页面可通过本机调试服务的 `/json/list` 发现目标并明确选择，也可直接输入外部标准 CDP WebSocket 地址，例如 `ws://127.0.0.1:9222/devtools/page/target-id`，点击连接，无需重启。仍兼容启动前的 `CAPX_CDP_WS`。切换目标前停止旧连接；目标需要已由使用者的调试工具提供 CDP。Capx 不内置微信版本 Hook 或未确认许可的调试组件。

以上功能提供代理路由、TLS 解密和界面自动化，不能保证所有 App 都使用代理或信任用户 CA。证书固定、QUIC 与业务层密文需要逐 App 验证，抓包链路就绪不等于已经得到接口明文。

## 验证范围

默认 Go 测试验证可控 WDA 服务的会话复用、截图原始数据与 points、元素定位、Unicode、失效会话、地址限制、平台隔离和双层授权。页面回归使用模拟设备与 Retina 图片。2026-10-15 集成验证时，本地 WDA 8100 端口不可用；没有将模拟验证记作 iPhone 实机通过。

使用前请阅读 [使用声明与免责声明](../DISCLAIMER.md)。
