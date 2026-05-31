# Link Launcher

本地链接跳转器，用来保存官方商品、车票、预约、候补或已有待付款订单链接，并在指定时间打开。

## 运行

```powershell
npm run dev:launcher
```

也可以直接打开：

```text
link-launcher/renderer/index.html
```

浏览器直接打开时只能使用浏览器的 `window.open`；Electron 运行时会调用系统默认处理器，因此已注册的官方 App URI 协议也可以交给系统处理。

## 边界

- 不会从普通商品链接伪造付款页。
- 不会自动提交订单、自动付款或绕过验证码。
- 只有你粘贴的是平台已经生成的待付款订单链接时，才可能打开到付款前页面。
