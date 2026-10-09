#!/usr/bin/env python3
"""
جمع‌کننده‌ی کانفیگ V2Ray و پروکسی MTProto از کانال‌های عمومی تلگرام.

- لیست کانال‌ها از channels.txt خونده می‌شه.
- صفحه‌ی عمومی هر کانال (t.me/s/اسم) دانلود می‌شه، پس نیازی به لاگین یا API key نیست.
- لینک‌های vless/vmess/trojan/ss/hysteria2/tuic و پروکسی‌های t.me/proxy بیرون کشیده می‌شن.
- سرورهایی که پورتشون باز نیست حذف می‌شن (این فقط یعنی سرور زنده‌ست، نه اینکه سریع باشه).
- خروجی‌ها: sub.txt، configs.txt، proxies.txt، PROXIES.md
"""
import base64
import json
import re
import socket
import sys
import time
import urllib.parse
import urllib.request
import html
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent

PAGES_PER_CHANNEL = 4      # از هر کانال چند صفحه (هر صفحه ~۲۰ پست) عقب بره
MAX_CONFIGS = 400
MAX_PROXIES = 120
TCP_TIMEOUT = 4            # ثانیه
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

V2RAY_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:vless|vmess|trojan|ss|hysteria2|hy2|tuic)://[^\s<>\"'`]+",
    re.I,
)
PROXY_RE = re.compile(
    r"(?:https?://t\.me/proxy|tg://proxy)\?[^\s<>\"'`]+",
    re.I,
)
POST_RE = re.compile(r'data-post="[^"/]+/(\d+)"')
TRAIL = ".,;:!?)]}»"


def fetch(url):
    err = None
    for _ in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=25) as r:
                return r.read().decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001
            err = e
            time.sleep(2)
    print(f"  ! خطا در دریافت {url}: {err}")
    return ""


def scrape_channel(name):
    """متن چند صفحه‌ی آخر کانال رو برمی‌گردونه."""
    texts = []
    url = f"https://t.me/s/{name}"
    for _ in range(PAGES_PER_CHANNEL):
        page = fetch(url)
        if not page:
            break
        texts.append(html.unescape(page))
        ids = [int(i) for i in POST_RE.findall(page)]
        if not ids:
            break
        oldest = min(ids)
        if oldest <= 1:
            break
        url = f"https://t.me/s/{name}?before={oldest}"
        time.sleep(1)
    return "\n".join(texts)


def norm_proxy(link):
    """(server, port, لینک تمیز) یا None."""
    try:
        query = link.split("?", 1)[1]
        d = urllib.parse.parse_qs(query)
        server = d["server"][0].strip()
        port = int(re.match(r"\d+", d["port"][0]).group(0))
        secret = re.match(r"[A-Za-z0-9_\-=]+", d["secret"][0].strip()).group(0)
    except Exception:  # noqa: BLE001
        return None
    if not server or not (0 < port < 65536):
        return None
    return server, port, f"https://t.me/proxy?server={server}&port={port}&secret={secret}"


def _b64decode(raw):
    raw = raw.replace("-", "+").replace("_", "/")
    raw += "=" * (-len(raw) % 4)
    return base64.b64decode(raw).decode("utf-8", "ignore")


def v2ray_host_port(link):
    """(host, port) یا None."""
    try:
        scheme, body = link.split("://", 1)
        scheme = scheme.lower()
        if scheme == "vmess":
            data = json.loads(_b64decode(body.split("#")[0]))
            return str(data["add"]), int(data["port"])
        u = urllib.parse.urlsplit(link)
        if scheme == "ss" and u.port is None:
            # شکل ss://BASE64#name  ->  method:pass@host:port
            dec = _b64decode(body.split("#")[0])
            hostport = dec.rsplit("@", 1)[1]
            host, port = hostport.rsplit(":", 1)
            return host.strip("[]"), int(port)
        if u.hostname and u.port:
            return u.hostname, u.port
    except Exception:  # noqa: BLE001
        pass
    return None


def tcp_ok(hp):
    host, port = hp
    try:
        with socket.create_connection((host, port), timeout=TCP_TIMEOUT):
            return True
    except Exception:  # noqa: BLE001
        return False


def keep_alive(items):
    """items: لیست (host, port, link). فقط اونایی که پورتشون باز نیست حذف می‌شن."""
    pairs = sorted({(h, p) for h, p, _ in items})
    with ThreadPoolExecutor(max_workers=64) as ex:
        results = dict(zip(pairs, ex.map(tcp_ok, pairs)))
    alive = [it for it in items if results.get((it[0], it[1]))]
    if not alive and items:
        print("  ! هیچ سروری جواب نداد (شاید تست شبکه خراب بود)؛ همه بدون فیلتر نگه داشته شدن.")
        return items
    return alive


def read_channels():
    lines = (ROOT / "channels.txt").read_text(encoding="utf-8").splitlines()
    out = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line.lstrip("@"))
    return out


def extract(text):
    """از یه متن، کانفیگ‌ها و پروکسی‌ها رو بیرون می‌کشه."""
    configs, proxies = {}, {}
    for m in V2RAY_RE.findall(text):
        link = m.rstrip(TRAIL)
        hp = v2ray_host_port(link)
        if not hp:
            continue
        key = link.split("#")[0]
        configs.setdefault(key, (hp[0], hp[1], link))
    for m in PROXY_RE.findall(text):
        res = norm_proxy(m.rstrip(TRAIL))
        if not res:
            continue
        server, port, clean = res
        proxies.setdefault(clean, (server, port, clean))
    return configs, proxies


def main():
    channels = read_channels()
    all_configs, all_proxies = {}, {}
    for ch in channels:
        print(f"> {ch}")
        c, p = extract(scrape_channel(ch))
        print(f"  کانفیگ: {len(c)} | پروکسی: {len(p)}")
        for k, v in c.items():
            all_configs.setdefault(k, v)
        for k, v in p.items():
            all_proxies.setdefault(k, v)

    configs = keep_alive(list(all_configs.values()))[:MAX_CONFIGS]
    proxies = keep_alive(list(all_proxies.values()))[:MAX_PROXIES]
    print(f"\nسالم: {len(configs)} کانفیگ، {len(proxies)} پروکسی")

    if not configs and not proxies:
        print("چیزی پیدا نشد؛ فایل‌های قبلی دست‌نخورده موندن.")
        return 0

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    if configs:
        links = [c[2] for c in configs]
        body = "\n".join(links) + "\n"
        (ROOT / "configs.txt").write_text(body, encoding="utf-8")
        (ROOT / "sub.txt").write_text(
            base64.b64encode(body.encode("utf-8")).decode("ascii"), encoding="utf-8"
        )

    if proxies:
        (ROOT / "proxies.txt").write_text(
            "\n".join(p[2] for p in proxies) + "\n", encoding="utf-8"
        )
        md = [
            "# پروکسی‌های تلگرام",
            "",
            f"آخرین آپدیت: {now}",
            "",
            "روی هر لینک بزن؛ تلگرام خودش می‌پرسه بخوای وصل بشی یا نه.",
            "",
        ]
        for i, (server, port, link) in enumerate(proxies, 1):
            md.append(f"{i}. [{server}:{port}]({link})")
        (ROOT / "PROXIES.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    (ROOT / "last_update.txt").write_text(
        f"{now}\nconfigs={len(configs)}\nproxies={len(proxies)}\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
