# Android 与 iOS 手机自动化

App 抓包页面提供统一的截图、元素树、点击、输入、滑动、启动 App 与返回桌面入口。平台分别使用 Android ADB 和 iOS WebDriverAgent（WDA）。HTTPS 抓包使用同一工作区的 MITM 代理与 CA。

## Android

1. 安装 Android Platform Tools，连接 USB，在手机上开启 USB 调试并授权电脑。
2. 在 App 抓包页选择 Android 和设备，开启主动操作，点击开始抓包。
3. 点击推送 CA，在手机上确认安装。自己的测试 App 需要信任测试 CA，应用的正式版可能不信任用户 CA。
4. 刷新截图，勾选点击截图操作手机，或者读取元素按文字/资源 ID 定位。

USB 抓包使用 `adb reverse`，手机代理 `127.0.0.1` 会转发到电脑。Wi-Fi 模式填写电脑局域网 IP，不能填手机自己的 loopback。Android 原生 ADB 输入仅支持可打印 ASCII，中文仍需输入法或其他自动化后端。

## iOS

1. 在 iPhone 上启动有效签名的 WDA XCTest，完成开发者模式与 UI 自动化授权，将 WDA 控制端口转发到电脑 loopback。例如电脑端地址为 `http://127.0.0.1:8100`。WDA 必须保持运行；只打开 Runner 图标不能替代启动 XCTest。
2. 在 App 抓包页选择 iOS，开启主动操作，填写 WDA 地址并连接。可选填写已有会话 ID；留空时查询当前 WDA 会话，没有会话时创建。切换控制服务或指定会话前先断开。
3. 刷新截图后可点击、输入中文、滑动、返回桌面或启动 App。微信的 iOS bundle ID 为 `com.tencent.xin`。iOS 没有 Android 通用返回键，使用页面的返回按钮或手势。
4. 抓包另行启用 Wi-Fi 代理入口，填写手机 IP 白名单，在 iPhone Wi-Fi 设置中填写电脑 IP 和代理端口。安装当前工作区的 CA，并在“设置 → 通用 → 关于本机 → 证书信任设置”开启完全信任。

WDA 控制授权与 HTTPS 证书信任是不同的系统设置。Capx 不自动安装 WDA、不分发签名证书或配对身份、不自动确认手机密码。断开 Capx 操作连接不会终止手机 App 或 XCTest，也不会修改抓包代理。

WDA 截图为像素，操作坐标为 UIKit points。页面自动换算；REST 截图附带 `X-Capx-Screen-Width`、`X-Capx-Screen-Height` 与 `X-Capx-Coordinate-Space: points`。屏幕旋转后先刷新截图。后台拒绝超出 points 范围的坐标，失效会话不会触发自动重试或重建；用户点击重新连接时会查询当前会话。

WDA 协议依据 [Appium WebDriverAgent](https://github.com/appium/WebDriverAgent)。签名有效期、设备系统支持及 USB 转发工具需按实际环境验证。

## MCP 示例

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

## 小程序与解密

小程序调试页面可直接输入外部标准 CDP WebSocket 地址，例如 `ws://127.0.0.1:9222/devtools/page/target-id`，点击连接，无需重启。仍兼容启动前的 `CAPX_CDP_WS`。切换目标前停止旧连接；目标需要已由使用者的调试工具提供 CDP。Capx 不内置微信版本 Hook 或未确认许可的调试组件。

以上功能提供代理路由、TLS 解密和界面自动化，不能保证所有 App 都使用代理或信任用户 CA。证书固定、QUIC 与业务层密文需要逐 App 验证，抓包链路就绪不等于已经得到接口明文。

## 验证范围

默认 Go 测试验证可控 WDA 服务的会话复用、截图原始数据与 points、元素定位、Unicode、失效会话、地址限制、平台隔离和双层授权。页面回归使用模拟设备与 Retina 图片。2026-10-15 集成验证时，本地 WDA 8100 端口不可用；没有将模拟验证记作 iPhone 实机通过。
