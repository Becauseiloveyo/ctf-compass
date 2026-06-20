# CTF Compass 中文说明

CTF Compass 是一个面向合法 CTF 训练和比赛的桌面附件分析工作台。它以附件为中心，把图片、文本、压缩包、流量包、二进制、磁盘镜像、音频和题面线索放在同一个本地分析流程里，尽量自动完成能确定的拆解、解码、提取和 flag 候选判断。

## 项目定位

- 本项目只用于 CTF、靶场、公开练习题和你明确授权的环境。
- 默认优先本地离线分析，不会把附件上传到第三方服务。
- 自动化目标是减少重复劳动，不保证每道题都能直接给出最终 flag。
- 找不到 flag 时，软件会保留证据、导出中间文件，并给出下一步人工检查方向。

## 主要能力

- 杂项与取证：文件魔数识别、strings、嵌入文件扫描、ZIP/GZIP/TAR/TGZ 递归解包、伪加密 ZIP 修复、PNG/BMP LSB、PNG 文本块、GIF 注释和描述符位流、JPEG 注释/XMP/APP 段、MP4 隐藏轨道和 chunk 表修复。
- 流量分析：pcap/pcapng 基础解析、HTTP/DNS/TLS SNI、Cookie/Token、HTTP 对象导出、multipart/form-data 上传文件提取、TCP/UDP 方向流重组、ICMP/DNS/IP 隐蔽信道候选、USB HID 键盘/鼠标/手柄恢复。
- 编码与密码：Base64/Base58/Base91/Base32、Hex、Ascii85/Z85、URL、Quoted-Printable、UUEncode、A1Z26、NATO、Morse、Polybius、Bacon、Brainfuck/Ook、零宽/空白隐写、ROT/Caesar、Affine、Rail Fence、单字节 XOR、常见 RSA 参数弱点。
- 逆向与 Pwn：ELF/PE/APK 基础结构、导入导出、strings、checksec-lite、seccomp-BPF、core dump 摘要、危险函数、ROP gadget 候选、AArch64/ARM/MIPS/RISC-V 轻量 gadget 扫描。
- Web 靶机：在授权前提下对本地、私网或明确授权的公网 CTF 目标做同源 GET 扫描，提取路由、脚本、注释、响应头、表单、source map、下载附件和直接 flag 候选。

## 快速开始

```powershell
npm install
npm run dev:electron
```

Web 预览：

```powershell
npm run dev
```

本地验证：

```powershell
npm run build:web
npm run smoke:desktop
npm run smoke:web
npm run smoke:analyzer
```

## 使用流程

1. 打开软件后添加题目附件，支持单文件或文件夹。
2. 可选填写题目标题、标签、描述和你已经观察到的线索。
3. 点击“自动求解”，软件会递归分析附件并生成中间文件。
4. 在“结果”和“附件”区域查看 flag 候选、提取过程、失败原因和下一步建议。
5. 必要时导出 Markdown 报告，保留解题路径和证据。

## 沙盒目录

软件会把生成文件、提取结果和临时会话集中放在 Electron `userData/sandbox/` 下。删除或清理沙盒不会删除你原始选择的题目附件。

沙盒主要目录：

- `generated/`：递归提取文件、报告、可视化图片和工具输出。
- `downloads/`：预留给未来便携工具下载。
- `tools/`：预留给未来本地 helper 工具。
- `session/`：临时会话状态，启动时会清空。

## 训练路线

中文训练矩阵见 [docs/ctf-training-plan-zh.md](docs/ctf-training-plan-zh.md)。该文档按题型列出需要覆盖的公开训练方向、软件应自动完成的动作、仍需人工判断的部分，以及对应 smoke 测试策略。

## 已知边界

- 深度密码学、复杂隐写、交互式 Pwn 利用链和需要远端状态的 Web 漏洞仍需要人工判断。
- 加密压缩包如果没有密码线索，只能提示候选密码来源和后续操作。
- 公网 Web 目标默认受限，只有明确授权后才应开启对应选项。
- 本项目不会替代 Wireshark、Ghidra、IDA、Burp、pwndbg 等专业工具；它优先做批量前处理、证据整理和可确定的自动化。

## 许可

MIT
