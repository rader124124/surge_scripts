# 阿维塔 App Surge 每日签到脚本

这个目录里有两个文件：

- `avatr_checkin.js`: Surge 脚本。会捕获本机登录态，每天刷新 token、生成新签名并签到。
- `avatr_checkin.sgmodule`: Surge module，可直接在 Surge 里通过 Raw URL 导入。

## 导入地址

```text
https://raw.githubusercontent.com/rader124124/surge_scripts/rm/avatr-checkin/avatr_checkin.sgmodule
```

## 使用流程

1. 在 iPhone 的 Surge 里开启 HTTPS 解密，并安装、信任 Surge CA 证书。
2. 在 Surge 里通过上面的 Raw URL 导入并启用 module。
3. 打开一次阿维塔 App，让它调用 `getNewToken`。你应该会收到“已更新登录态”的通知。
4. 进入一次“积分/任务中心”页面。你应该会收到“已捕获签到上下文”的通知。
5. 之后 cron 会在每天 09:15 自动执行。你也可以改 `cronexp`。

## 抓包里确认到的接口

- 签到接口：`POST https://m.avatr.com/api/v6/signIn/signInRiskVerify`
- 查询积分：`GET https://m.avatr.com/api/v6/signIn/pointValue`
- 查询周签到信息：`POST https://m.avatr.com/api/v6/signIn/info`
- 刷新登录态：`POST https://appserver-view.avatr.com/v5/base-view/auth/getNewToken`

H5 里的签名逻辑是：`x-avatr-expire` 用当前秒级时间戳，随机生成 32 位 salt，用 RSA 公钥加密成 `x-avatr-secret`，再对 `{ expire, params, request: { body, content-type }, salt }` 做 SHA-256 得到 `x-avatr-sign`。脚本已内置这套逻辑。

## 注意

- 不要把 HAR、Surge persistent store、`login-token`、`refreshToken`、Cookie、手机号、车辆 VIN、设备 ID 发到公开地方。
- 如果后续阿维塔调整风控，可能需要重新打开 App 和积分页刷新一次捕获上下文。
- 这个脚本不处理短信验证码或图形验证码，只使用你自己已经登录的 App 会话。
