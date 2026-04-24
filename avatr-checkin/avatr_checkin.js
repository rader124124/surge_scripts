/*
 * AVATR daily check-in for Surge.
 *
 * What this script does:
 * 1. Captures your own AVATR login/refresh token and H5 request context.
 * 2. Generates fresh AVATR v5/v6 request signatures for every cron run.
 * 3. Refreshes login-token, then calls the real sign-in API.
 *
 * It does not bypass SMS verification or captcha. Import the module, open the
 * AVATR app once, then enter the points/task page once so Surge can capture
 * your own authorized session into local persistent storage.
 */

const CONFIG = {
  title: "阿维塔每日签到",
  authKey: "avatr.checkin.auth.v2",
  h5ContextKey: "avatr.checkin.h5Context.v2",
  refreshUrl: "https://appserver-view.avatr.com/v5/base-view/auth/getNewToken",
  signInUrl: "https://m.avatr.com/api/v6/signIn/signInRiskVerify",
  taskCenterUrl: "https://m.avatr.com/activities/community/taskCenter?isFullScreen=true&freshValue=1",
  appVersion: "4.7.6",
  os: "IOS",
  application: "AVATR_APP",
  timeout: 30000,
  notifyOnCapture: true,
  notifyOnSuccess: true,
  notifyOnFailure: true
};

const AVATR_PUBLIC_KEY_MODULUS_HEX =
  "99ADD9FCCC3ACDDB09347B2DDF3B2F40AE2B2BE516EA4FA6C075ADEBC2D7FC773D577631A90A9E815ED248860291D578FBFF4810C01FE7CA4711E43C9C9F90BF6A05E0C49A2205B6256A2605EF41FBE3C9CF3333C03EDF6F282E32EE5077A1082CB7F30E9B3761CD64A61F97A553CF6FCDD95E50BC93BEC4001DA4BCBC6ECA2D";
const AVATR_PUBLIC_KEY_EXPONENT = 65537n;

const hasRequest = typeof $request !== "undefined" && $request && $request.url;
const hasResponse = typeof $response !== "undefined" && $response;

if (hasResponse && /\/v5\/base-view\/auth\/getNewToken(?:\?|$)/.test($request.url)) {
  captureAuthResponse();
} else if (hasRequest && /\/api\/v6\/signIn\//.test($request.url)) {
  captureH5Context();
} else {
  runDailyCheckIn();
}

function captureAuthResponse() {
  const auth = readJson(CONFIG.authKey, {});
  const requestHeaders = $request.headers || {};
  const response = parseJson($response.body || "");
  const requestBody = parseJson($request.body || "");
  const result = response && response.result ? response.result : {};

  const nextAuth = {
    ...auth,
    loginToken: result.loginToken || auth.loginToken || getHeader(requestHeaders, "login-token") || "",
    refreshToken: result.refreshToken || auth.refreshToken || (requestBody && requestBody.refreshToken) || "",
    nativeHeaders: pickHeaders(requestHeaders, [
      "Accept",
      "Content-Type",
      "APP-VERSION",
      "APPLICATION",
      "OS",
      "CHANNEL",
      "SYSTEM_VERSION",
      "PHONE-MODEL",
      "DEVICE-NUMBER",
      "User-Agent",
      "Accept-Language"
    ]),
    capturedAt: new Date().toISOString()
  };

  writeJson(CONFIG.authKey, nextAuth);

  if (CONFIG.notifyOnCapture && (nextAuth.loginToken || nextAuth.refreshToken)) {
    notify(CONFIG.title, "已更新登录态", tokenExpiryText(nextAuth.loginToken));
  }

  done({});
}

function captureH5Context() {
  const headers = $request.headers || {};
  const loginToken = getHeader(headers, "login-token") || extractTokenFromUserAgent(getHeader(headers, "User-Agent"));
  const context = {
    loginToken,
    userAgent: getHeader(headers, "User-Agent") || "",
    cookie: getHeader(headers, "Cookie") || "",
    riskBlackBox: getHeader(headers, "sm-risk-black-box") || "",
    appVersion: getHeader(headers, "APP-VERSION") || CONFIG.appVersion,
    os: getHeader(headers, "OS") || CONFIG.os,
    application: getHeader(headers, "APPLICATION") || CONFIG.application,
    acceptLanguage: getHeader(headers, "Accept-Language") || "",
    capturedFrom: $request.url,
    capturedAt: new Date().toISOString()
  };

  writeJson(CONFIG.h5ContextKey, context);

  if (loginToken) {
    const auth = readJson(CONFIG.authKey, {});
    writeJson(CONFIG.authKey, {
      ...auth,
      loginToken,
      capturedAt: auth.capturedAt || context.capturedAt
    });
  }

  if (CONFIG.notifyOnCapture) {
    notify(CONFIG.title, "已捕获签到上下文", safePath($request.url));
  }

  done({});
}

function runDailyCheckIn() {
  const auth = readJson(CONFIG.authKey, {});
  const context = readJson(CONFIG.h5ContextKey, {});

  if (!auth.loginToken && !auth.refreshToken && !context.loginToken) {
    notify(
      CONFIG.title,
      "缺少登录态",
      "先打开阿维塔 App，再进入积分/任务中心页面，让 Surge 捕获一次。"
    );
    return done();
  }

  refreshLoginToken(auth, (freshAuth) => {
    const loginToken = freshAuth.loginToken || context.loginToken;
    if (!loginToken) {
      if (CONFIG.notifyOnFailure) {
        notify(CONFIG.title, "缺少 login-token", "请重新打开阿维塔 App 捕获登录态。");
      }
      return done();
    }
    signIn(loginToken, context);
  });
}

function refreshLoginToken(auth, callback) {
  if (!auth.refreshToken) {
    return callback(auth);
  }

  const data = {
    isForce: false,
    refreshToken: auth.refreshToken
  };
  const headers = buildRefreshHeaders(auth);
  const signed = signRequest({
    method: "POST",
    url: CONFIG.refreshUrl,
    headers,
    data
  });

  $httpClient.post(
    {
      url: CONFIG.refreshUrl,
      headers: signed.headers,
      body: signed.body,
      timeout: CONFIG.timeout
    },
    (error, response, body) => {
      if (error) {
        if (CONFIG.notifyOnFailure) {
          notify(CONFIG.title, "刷新登录态失败", stringifyError(error));
        }
        return callback(auth);
      }

      const parsed = parseJson(body || "");
      if (!isApiSuccess(response, parsed) || !parsed.result) {
        if (CONFIG.notifyOnFailure) {
          notify(CONFIG.title, "刷新登录态未成功", responseSummary(response, body));
        }
        return callback(auth);
      }

      const nextAuth = {
        ...auth,
        loginToken: parsed.result.loginToken || auth.loginToken || "",
        refreshToken: parsed.result.refreshToken || auth.refreshToken || "",
        refreshedAt: new Date().toISOString()
      };
      writeJson(CONFIG.authKey, nextAuth);
      callback(nextAuth);
    }
  );
}

function signIn(loginToken, context) {
  const data = {};
  const headers = buildH5Headers(loginToken, context);
  const signed = signRequest({
    method: "POST",
    url: CONFIG.signInUrl,
    headers,
    data
  });

  $httpClient.post(
    {
      url: CONFIG.signInUrl,
      headers: signed.headers,
      body: signed.body,
      timeout: CONFIG.timeout
    },
    (error, response, body) => {
      if (error) {
        if (CONFIG.notifyOnFailure) {
          notify(CONFIG.title, "签到请求失败", stringifyError(error));
        }
        return done();
      }

      const parsed = parseJson(body || "");
      const result = analyzeSignInResult(response, parsed, body);

      if (result.ok && CONFIG.notifyOnSuccess) {
        notify(CONFIG.title, result.subtitle, result.body);
      }

      if (!result.ok && CONFIG.notifyOnFailure) {
        notify(CONFIG.title, result.subtitle, result.body);
      }

      done();
    }
  );
}

function buildRefreshHeaders(auth) {
  const saved = auth.nativeHeaders || {};
  const headers = {
    Accept: saved.Accept || "application/json",
    "Content-Type": saved["Content-Type"] || "application/json",
    APPLICATION: saved.APPLICATION || CONFIG.application,
    OS: saved.OS || CONFIG.os,
    "APP-VERSION": saved["APP-VERSION"] || CONFIG.appVersion
  };

  copyIfPresent(headers, saved, "CHANNEL");
  copyIfPresent(headers, saved, "SYSTEM_VERSION");
  copyIfPresent(headers, saved, "PHONE-MODEL");
  copyIfPresent(headers, saved, "DEVICE-NUMBER");
  copyIfPresent(headers, saved, "Accept-Language");

  if (auth.loginToken) headers["login-token"] = auth.loginToken;
  if (saved["User-Agent"]) headers["User-Agent"] = saved["User-Agent"];

  return headers;
}

function buildH5Headers(loginToken, context) {
  const userAgent = withUserAgentToken(context.userAgent, loginToken);
  const headers = {
    Accept: "application/json, text/plain, */*",
    "Content-Type": "application/json",
    Origin: "https://m.avatr.com",
    Referer: CONFIG.taskCenterUrl,
    OS: context.os || CONFIG.os,
    APPLICATION: context.application || CONFIG.application,
    "APP-VERSION": context.appVersion || CONFIG.appVersion,
    "login-token": loginToken
  };

  if (userAgent) headers["User-Agent"] = userAgent;
  if (context.cookie) headers.Cookie = context.cookie;
  if (context.riskBlackBox) headers["sm-risk-black-box"] = context.riskBlackBox;
  if (context.acceptLanguage) headers["Accept-Language"] = context.acceptLanguage;

  return headers;
}

function signRequest(options) {
  const method = String(options.method || "GET").toLowerCase();
  const headers = { ...(options.headers || {}) };
  const body = typeof options.data === "undefined" || options.data === null ? "" : JSON.stringify(options.data);
  const contentType = headers["Content-Type"] || (method === "get" ? "" : "application/json");
  const expire = Math.trunc(new Date().getTime() / 1000);
  const salt = uuidV4Hex();
  const secret = rsaEncryptPkcs1v15(salt);
  const params = [];

  if (options.params) {
    Object.keys(options.params).forEach((key) => {
      params.push(`${key}=${encodeURIComponent(options.params[key])}`);
    });
  }

  const signPayload = {
    expire,
    params: params.sort(),
    request: {
      body,
      "content-type": contentType
    },
    salt
  };

  const sign = sha256(JSON.stringify(signPayload));

  return {
    headers: {
      ...headers,
      "x-avatr-sign": sign,
      "x-avatr-secret": secret,
      "x-avatr-expire": String(expire)
    },
    body
  };
}

function analyzeSignInResult(response, parsed, rawBody) {
  const status = Number(response && (response.status || response.statusCode || response.responseCode));

  if (!status || status < 200 || status >= 300) {
    return {
      ok: false,
      subtitle: `HTTP ${status || "未知"}`,
      body: truncate(rawBody || "没有返回内容。", 180)
    };
  }

  if (!parsed) {
    return {
      ok: false,
      subtitle: "无法解析返回",
      body: truncate(rawBody || "", 180)
    };
  }

  if (parsed.code === 0) {
    const result = parsed.result || {};
    const point = typeof result.todayPointValue !== "undefined" ? `+${result.todayPointValue} 积分` : "成功";
    const days = result.continueSignInDays ? `连续 ${result.continueSignInDays} 天` : "";
    const message = result.successMessage || parsed.message || "";
    return {
      ok: true,
      subtitle: `签到完成 ${point}`,
      body: [days, message].filter(Boolean).join("，") || "success"
    };
  }

  const message = parsed.message || parsed.msg || rawBody || "接口返回非成功状态。";
  const alreadyDone = /已签到|重复|今日.*签到|already/i.test(message);
  return {
    ok: alreadyDone,
    subtitle: alreadyDone ? "今天可能已签到" : `签到失败 code=${parsed.code}`,
    body: truncate(message, 180)
  };
}

function isApiSuccess(response, parsed) {
  const status = Number(response && (response.status || response.statusCode || response.responseCode));
  return status >= 200 && status < 300 && parsed && parsed.code === 0;
}

function responseSummary(response, body) {
  const status = response && (response.status || response.statusCode || response.responseCode);
  const parsed = parseJson(body || "");
  return truncate((parsed && (parsed.message || parsed.msg)) || body || `HTTP ${status || "未知"}`, 180);
}

function readJson(key, fallback) {
  const raw = $persistentStore.read(key);
  if (!raw) return fallback;
  return parseJson(raw) || fallback;
}

function writeJson(key, value) {
  return $persistentStore.write(JSON.stringify(value), key);
}

function pickHeaders(headers, names) {
  const output = {};
  names.forEach((name) => {
    const value = getHeader(headers, name);
    if (value) output[name] = value;
  });
  return output;
}

function getHeader(headers, name) {
  const target = String(name).toLowerCase();
  const keys = Object.keys(headers || {});
  for (const key of keys) {
    if (String(key).toLowerCase() === target) return headers[key];
  }
  return "";
}

function copyIfPresent(target, source, name) {
  if (source && source[name]) target[name] = source[name];
}

function withUserAgentToken(userAgent, token) {
  if (!userAgent) return "";
  if (/token=[^;)]*/.test(userAgent)) {
    return userAgent.replace(/token=[^;)]*/, `token=${token}`);
  }
  return userAgent;
}

function extractTokenFromUserAgent(userAgent) {
  const match = String(userAgent || "").match(/token=([^;)]*)/);
  return match ? match[1] : "";
}

function tokenExpiryText(token) {
  const payload = decodeJwtPayload(token);
  if (!payload || !payload.exp) return "已保存到 Surge 本机。";
  const date = new Date(Number(payload.exp) * 1000);
  return `login-token 过期时间：${formatDate(date)}`;
}

function decodeJwtPayload(token) {
  const parts = String(token || "").split(".");
  if (parts.length < 2) return null;
  try {
    return JSON.parse(base64UrlDecode(parts[1]));
  } catch (_) {
    return null;
  }
}

function parseJson(text) {
  if (!text || typeof text !== "string") return null;
  try {
    return JSON.parse(text);
  } catch (_) {
    return null;
  }
}

function safePath(url) {
  const match = String(url || "").match(/^https?:\/\/[^/]+([^?#]*)/i);
  return match ? match[1] || "/" : String(url || "");
}

function truncate(text, length) {
  const value = String(text || "");
  return value.length > length ? `${value.slice(0, length)}...` : value;
}

function stringifyError(error) {
  if (typeof error === "string") return error;
  try {
    return JSON.stringify(error);
  } catch (_) {
    return String(error);
  }
}

function formatDate(date) {
  const pad = (value) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function notify(title, subtitle, body) {
  $notification.post(title, subtitle || "", body || "");
}

function done(value) {
  if (typeof $done === "function") {
    $done(value);
  }
}

function uuidV4Hex() {
  const bytes = randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  return bytesToHex(bytes);
}

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
    return bytes;
  }
  for (let i = 0; i < length; i += 1) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
  return bytes;
}

function rsaEncryptPkcs1v15(message) {
  const messageBytes = utf8Bytes(message);
  const keyBytes = 128;
  if (messageBytes.length > keyBytes - 11) {
    throw new Error("RSA message too long");
  }

  const paddingLength = keyBytes - messageBytes.length - 3;
  const block = new Uint8Array(keyBytes);
  block[0] = 0;
  block[1] = 2;

  let offset = 2;
  while (offset < 2 + paddingLength) {
    const value = randomBytes(1)[0];
    if (value !== 0) {
      block[offset] = value;
      offset += 1;
    }
  }

  block[offset] = 0;
  block.set(messageBytes, offset + 1);

  const m = bytesToBigInt(block);
  const n = BigInt(`0x${AVATR_PUBLIC_KEY_MODULUS_HEX}`);
  const encrypted = modPow(m, AVATR_PUBLIC_KEY_EXPONENT, n);
  return base64EncodeBytes(bigIntToBytes(encrypted, keyBytes));
}

function modPow(base, exponent, modulus) {
  let result = 1n;
  let b = base % modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus;
    e >>= 1n;
    b = (b * b) % modulus;
  }
  return result;
}

function bytesToBigInt(bytes) {
  return BigInt(`0x${bytesToHex(bytes)}`);
}

function bigIntToBytes(value, length) {
  let hex = value.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  const bytes = hexToBytes(hex);
  if (bytes.length === length) return bytes;
  const output = new Uint8Array(length);
  output.set(bytes, length - bytes.length);
  return output;
}

function hexToBytes(hex) {
  const clean = String(hex || "");
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.slice(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  let output = "";
  for (let i = 0; i < bytes.length; i += 1) {
    output += bytes[i].toString(16).padStart(2, "0");
  }
  return output;
}

function utf8Bytes(text) {
  const bytes = [];
  const input = String(text);
  for (let i = 0; i < input.length; i += 1) {
    let codePoint = input.charCodeAt(i);
    if (codePoint >= 0xd800 && codePoint <= 0xdbff && i + 1 < input.length) {
      const next = input.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        codePoint = 0x10000 + ((codePoint - 0xd800) << 10) + (next - 0xdc00);
        i += 1;
      }
    }

    if (codePoint < 0x80) {
      bytes.push(codePoint);
    } else if (codePoint < 0x800) {
      bytes.push(0xc0 | (codePoint >> 6));
      bytes.push(0x80 | (codePoint & 0x3f));
    } else if (codePoint < 0x10000) {
      bytes.push(0xe0 | (codePoint >> 12));
      bytes.push(0x80 | ((codePoint >> 6) & 0x3f));
      bytes.push(0x80 | (codePoint & 0x3f));
    } else {
      bytes.push(0xf0 | (codePoint >> 18));
      bytes.push(0x80 | ((codePoint >> 12) & 0x3f));
      bytes.push(0x80 | ((codePoint >> 6) & 0x3f));
      bytes.push(0x80 | (codePoint & 0x3f));
    }
  }
  return new Uint8Array(bytes);
}

function base64UrlDecode(input) {
  let value = String(input || "").replace(/-/g, "+").replace(/_/g, "/");
  while (value.length % 4) value += "=";
  return base64DecodeToString(value);
}

function base64DecodeToString(input) {
  if (typeof atob === "function") {
    return decodeURIComponent(
      atob(input)
        .split("")
        .map((char) => `%${char.charCodeAt(0).toString(16).padStart(2, "0")}`)
        .join("")
    );
  }

  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const clean = String(input || "").replace(/=+$/, "");
  const bytes = [];
  let buffer = 0;
  let bits = 0;
  for (let i = 0; i < clean.length; i += 1) {
    const index = chars.indexOf(clean[i]);
    if (index < 0) continue;
    buffer = (buffer << 6) | index;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  return decodeUtf8(new Uint8Array(bytes));
}

function base64EncodeBytes(bytes) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let output = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const b = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const c = i + 2 < bytes.length ? bytes[i + 2] : 0;
    const triple = (a << 16) | (b << 8) | c;
    output += chars[(triple >> 18) & 63];
    output += chars[(triple >> 12) & 63];
    output += i + 1 < bytes.length ? chars[(triple >> 6) & 63] : "=";
    output += i + 2 < bytes.length ? chars[triple & 63] : "=";
  }
  return output;
}

function decodeUtf8(bytes) {
  let output = "";
  for (let i = 0; i < bytes.length; i += 1) {
    const byte = bytes[i];
    if (byte < 0x80) {
      output += String.fromCharCode(byte);
    } else if (byte >= 0xc0 && byte < 0xe0) {
      const next = bytes[++i];
      output += String.fromCharCode(((byte & 0x1f) << 6) | (next & 0x3f));
    } else if (byte >= 0xe0 && byte < 0xf0) {
      const b2 = bytes[++i];
      const b3 = bytes[++i];
      output += String.fromCharCode(((byte & 0x0f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f));
    } else {
      const b2 = bytes[++i];
      const b3 = bytes[++i];
      const b4 = bytes[++i];
      const codePoint =
        ((byte & 0x07) << 18) | ((b2 & 0x3f) << 12) | ((b3 & 0x3f) << 6) | (b4 & 0x3f);
      const adjusted = codePoint - 0x10000;
      output += String.fromCharCode(0xd800 + (adjusted >> 10), 0xdc00 + (adjusted & 0x3ff));
    }
  }
  return output;
}

function sha256(message) {
  const bytes = utf8Bytes(message);
  const bitLength = bytes.length * 8;
  const withOne = bytes.length + 1;
  const paddedLength = Math.ceil((withOne + 8) / 64) * 64;
  const padded = new Uint8Array(paddedLength);
  padded.set(bytes);
  padded[bytes.length] = 0x80;

  const view = new DataView(padded.buffer);
  const high = Math.floor(bitLength / 0x100000000);
  const low = bitLength >>> 0;
  view.setUint32(paddedLength - 8, high);
  view.setUint32(paddedLength - 4, low);

  const k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2
  ];
  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;
  const w = new Uint32Array(64);

  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i += 1) {
      w[i] = view.getUint32(offset + i * 4);
    }
    for (let i = 16; i < 64; i += 1) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = add32(w[i - 16], s0, w[i - 7], s1);
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let i = 0; i < 64; i += 1) {
      const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = add32(h, s1, ch, k[i], w[i]);
      const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = add32(s0, maj);
      h = g;
      g = f;
      f = e;
      e = add32(d, temp1);
      d = c;
      c = b;
      b = a;
      a = add32(temp1, temp2);
    }

    h0 = add32(h0, a);
    h1 = add32(h1, b);
    h2 = add32(h2, c);
    h3 = add32(h3, d);
    h4 = add32(h4, e);
    h5 = add32(h5, f);
    h6 = add32(h6, g);
    h7 = add32(h7, h);
  }

  return [h0, h1, h2, h3, h4, h5, h6, h7]
    .map((value) => value.toString(16).padStart(8, "0"))
    .join("");
}

function rotr(value, shift) {
  return (value >>> shift) | (value << (32 - shift));
}

function add32() {
  let result = 0;
  for (let i = 0; i < arguments.length; i += 1) {
    result = (result + (arguments[i] >>> 0)) >>> 0;
  }
  return result;
}
