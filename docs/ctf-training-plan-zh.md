# CTF Compass 题型训练与能力补全计划

本计划用于驱动 CTF Compass 的本地自动化能力建设。项目不收录或再分发第三方题目附件；训练时只记录公开来源、题型模式、复现命令和能力差距。

## 参考资料

- [CTF Field Guide: Forensics](https://trailofbits.github.io/ctf/forensics/)：取证题常见文件格式、魔数、文件雕刻、strings、编码识别和二进制处理方法。
- [binwalk](https://github.com/ReFirmLabs/binwalk)：文件雕刻和嵌入载荷识别的代表工具，软件内置 `binwalk-lite` 应覆盖常见魔数扫描和递归解包。
- [zsteg](https://github.com/zed-0xff/zsteg)：PNG/BMP 低位平面隐写扫描的代表工具，软件内置 `zsteg-lite` 应覆盖常见通道、bit plane、位序和遍历顺序。
- [Wireshark Documentation](https://www.wireshark.org/docs/)：流量题人工验证的标准工具文档，软件内置 `tshark-lite` 应优先覆盖 HTTP、DNS、TLS、对象导出和常见 covert channel。

## 训练原则

- 先覆盖高频确定性流程，再处理需要猜测或交互的题型。
- 每补一个能力，必须增加 smoke fixture 或公开题复现记录。
- 不把随机字符串、占位 flag、示例 flag 当成已解结果。
- 所有生成文件放入沙盒，保留中间证据，失败时输出可操作下一步。

## 杂项与取证矩阵

| 题型 | 自动化目标 | 当前状态 | 下一步 |
| --- | --- | --- | --- |
| 文件魔数与附加数据 | 识别嵌入 ZIP/GZIP/TAR/PNG/PDF/ELF/RAR/7Z，导出并递归分析 | 已覆盖主流魔数和递归解包 | 增加更多容器格式和冲突魔数过滤 |
| 图片隐写 | PNG 文本块、PNG/BMP LSB、JPEG 注释/XMP/APP、GIF 扩展块、二维码/条码/OCR | 已覆盖基础与多种公开题模式 | 增加调色板索引 LSB、alpha 通道模式和更细的 zsteg 排序 |
| 压缩包 | ZIP 注释、伪加密修复、TGZ/TAR 递归、密码线索提取 | 已覆盖 | 增加 7z/rar 只读结构提示和密码候选评分 |
| 文本编码 | 多层 base、hex、url、quoted-printable、morse、polybius、bacon、xor、rail fence 等 | 已覆盖大量确定性链 | 增加更严格的误报过滤和明文语言评分 |
| pcap/pcapng | HTTP/DNS/TLS、cookie/token、HTTP 对象、multipart 上传文件、stream、ICMP/DNS/IP covert、USB HID | 已覆盖，新增 multipart 上传文件提取 | 增加 TFTP/FTP/SMTP 简单对象恢复 |
| 磁盘/内存 | MBR/GPT、常见 FS 指纹、小分区导出、minidump/raw memory 指标 | 已覆盖基础 | 增加 registry/event log/SQLite 指纹 |
| 音频/信号 | WAV metadata、PCM LSB、DTMF、Morse、tone map、VCD SPI/UART/I2C、CAN/csv | 已覆盖多类 | 增加 FSK/ASK 基础候选 |

## Web 矩阵

| 题型 | 自动化目标 | 当前状态 | 下一步 |
| --- | --- | --- | --- |
| 本地/授权目标爬取 | URL 归一化、同源 GET、robots/sitemap/source-map、注释/响应头/表单 | 已覆盖 | 增加更好的结果分组和重复页面去重 |
| 下载附件回流 | 下载 zip/png/txt/pcap/bin 并送入本地递归分析 | 已覆盖 | 增加 MIME 与扩展名冲突提示 |
| Token/Cookie 线索 | 从响应、脚本、pcap、表单提取 token/cookie/session | 已覆盖基础 | 增加 JWT header/payload 本地解码和弱 secret 提示 |
| 漏洞利用 | 需要交互、登录、payload 或远端状态 | 保持人工引导 | 只提供 checklist，不做未授权攻击自动化 |

## Reverse / Pwn 矩阵

| 题型 | 自动化目标 | 当前状态 | 下一步 |
| --- | --- | --- | --- |
| ELF/PE/APK 初筛 | header、section、import/export、strings、架构、依赖、DEX/APK 基础信息 | 已覆盖 | 增加 PE 保护项和 APK resource 细节 |
| Pwn 静态 triage | checksec-lite、危险函数、I/O 模式、seccomp、ROP gadget、core dump | 已覆盖 x86/x64 与多架构基础 | 增加 ret2csu、SROP、one_gadget 条件提示 |
| 利用链生成 | 需要远端环境、libc、交互和 crash 验证 | 不自动生成最终 exploit | 生成 pwndbg/pwntools 检查步骤 |

## 新增验证项记录

| 日期 | 能力 | Smoke 用例 | 结果 |
| --- | --- | --- | --- |
| 2026-06-20 | HTTP multipart/form-data 上传文件提取 | `http-multipart-upload` | 从 pcap 中导出 `flag.txt`，递归分析得到 `flag{http_multipart_upload_smoke}` |

## 后续优先级

1. TFTP/FTP/SMTP 简单对象恢复，补齐常见 pcap 附件传输题。
2. PNG 调色板/alpha LSB 和更多 zsteg 风格组合。
3. JWT 本地解码与弱 secret 字典提示，服务 Web 和流量题。
4. PE checksec-lite 和 APK resource-id 映射。
5. 文档页加入“失败任务如何继续”的中文指南。
