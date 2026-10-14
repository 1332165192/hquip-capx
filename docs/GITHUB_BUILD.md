# GitHub 编译和下载

只上传本公开源码目录的内容到仓库根目录，包括 `.github`、三个 Go 模块、Rust/C 源码、前端资源、许可证与构建配置。不要把 ZIP 文件本身当作唯一的仓库文件；需要先解压，让 `.github/workflows/build.yml` 位于仓库根目录对应的位置。

提交源码后，`build-artifacts` 工作流自动运行。也可打开 GitHub 的 Actions → build-artifacts → Run workflow 手动运行。不需要把本地 EXE、DLL、静态库、驱动、截图或账号资料提交进仓库。

| 工作 | 编译内容 | 下载产物 |
| --- | --- | --- |
| applications / Windows x64 | 后台、MCP、Chromium 启动器、管理端、Wails 桌面端 | capx-windows-amd64 |
| applications / Linux x64 | 同上，使用 GTK/WebKit 桌面依赖 | capx-linux-amd64 |
| applications / macOS ARM64 | 同上，Wails `.app` 内放置后台 | capx-macos-arm64 |
| native / 三个平台 | Rust 扫描库；Windows 编译 C/MinHook DLL，并检查 Windows pcap、Rust FFI、WinDivert、原生 Hook、gRPC 的 Go 编译 | capx-native-* |
| native-go / Linux | pcap、Rust FFI、NFQUEUE、gRPC 构建标签的集成测试和编译 | 验证日志 |

构建成功后，在对应 Actions 运行页面底部的 **Artifacts** 下载程序 ZIP 和 SHA-256 文件。应用包内同时包含许可证、第三方声明和构建提交信息。工作流只上传构建产物，不将二进制写回源码仓库，也不自动创建 GitHub Release。Artifact 默认保留14天，长期发行可由仓库维护者将校验过的产物发布到 Releases。

程序名称：`capx-captured` 为后台，`capx-mcp` 为 MCP，`capx-web-manager` 为管理端，`capx-desktop` 为 Wails 桌面端，`capx-launcher` 为 Chromium 窗口启动器；Windows 文件带 `.exe`。两种桌面入口均能使用独立编译的后台。

Go 固定为1.26.9，Wails CLI 为2.12.0，Rust 为1.95.0。Windows 使用托管 runner 的 Visual C++ 编译 C Hook，使用 LLVM/LLD 和匹配的 Rust GNU 库编译 Rust。Linux 工作流安装 GTK3/WebKit4.1 和 pcap 开发头文件；这些依赖只出现在编译机，不提交进仓库。

编译本公开仓库的源码不包含编译腾讯微信客户端、Npcap/WinDivert 驱动、WDA、第三方 F12 提供方或 iOS 签名包。它们需要由使用者独立安装或提供；GitHub 编译不会新增尚未集成的手机能力。

此工作流已做本地配置和脚本检查；当前没有远程仓库地址，因此尚未在你的 GitHub 仓库执行。首次上传后，以 Actions 的实际结果为准。无需在工作流 Secrets 里填写个人 DNSLog Key、手机密码或锁屏凭据。
