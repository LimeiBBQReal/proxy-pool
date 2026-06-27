"""
云端代理池测活器 — GitHub Actions 运行

功能:
  1. 从 sources.json 拉取所有代理源
  2. 去重合并
  3. 并发测活 (单探针 google_204, 4s 超时)
  4. 输出 alive/http.txt, alive/socks5.txt, alive/meta.json
  5. 自动 git commit (由 workflow 完成)

设计原则:
  - 快: 单探针 + 4s 超时 + 100 并发 → 10 分钟可测 10000+
  - 稳: 每个源独立 try/except, 一个挂不影响全局
  - 简: 输出纯 txt, 本地拉取零依赖
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import requests

ROOT = Path(__file__).resolve().parent
ALIVE_DIR = ROOT / "alive"
ALIVE_DIR.mkdir(exist_ok=True)

IP_PORT_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})")
SOCKS5_PORTS = {1080, 10808, 9050, 9150, 1081, 1086, 7890}


def load_config() -> dict[str, Any]:
    cfg_path = ROOT / "sources.json"
    return json.loads(cfg_path.read_text(encoding="utf-8"))


def guess_protocol(line: str, port: int, source_type: str) -> str:
    """根据源声明 + 行内容 + 端口启发式判断协议."""
    if source_type == "http":
        return "http"
    if source_type == "socks5":
        return "socks5"
    # mixed / unknown → 启发式
    lower = line.lower()
    if "socks5" in lower or "s5" in lower:
        return "socks5"
    if "socks4" in lower or "s4" in lower:
        return "socks5"
    if port in SOCKS5_PORTS:
        return "socks5"
    return "http"


def fetch_source(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """拉取单个代理源, 返回 [{ip, port, protocol, source}, ...]."""
    name = entry.get("name", "unknown")
    url = entry.get("url", "")
    source_type = entry.get("type", "mixed")
    if not url:
        return []

    try:
        r = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        r.raise_for_status()
        text = r.text
    except Exception as e:
        print(f"  [WARN] {name}: {e}", file=sys.stderr)
        return []

    proxies: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = IP_PORT_RE.search(line)
        if not m:
            continue
        ip = m.group(1)
        port = int(m.group(2))
        if port < 1 or port > 65535:
            continue
        proto = guess_protocol(line, port, source_type)
        proxies.append({"ip": ip, "port": port, "protocol": proto, "source": name})

    print(f"  [OK] {name}: {len(proxies)} 条", file=sys.stderr)
    return proxies


def collect_all(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """拉取所有源并去重."""
    print(f"[1/4] 拉取 {len(sources)} 个代理源...", file=sys.stderr)
    pool: list[dict[str, Any]] = []
    for entry in sources:
        pool.extend(fetch_source(entry))

    # 去重 (ip:port 唯一, 保留第一次出现的协议)
    seen: set[str] = set()
    uniq: list[dict[str, Any]] = []
    for p in pool:
        k = f"{p['ip']}:{p['port']}"
        if k not in seen:
            seen.add(k)
            uniq.append(p)

    proto_counts: dict[str, int] = {}
    for p in uniq:
        proto_counts[p["protocol"]] = proto_counts.get(p["protocol"], 0) + 1

    print(
        f"  合计 {len(uniq)} 个唯一代理 (原始 {len(pool)}), 协议: {proto_counts}",
        file=sys.stderr,
    )
    return uniq


def build_proxy_dict(ip: str, port: int, protocol: str) -> dict[str, str]:
    if protocol == "socks5":
        url = f"socks5://{ip}:{port}"
        return {"http": url, "https": url}
    return {"http": f"http://{ip}:{port}", "https": f"http://{ip}:{port}"}


def probe_one(proxy: dict[str, Any], probe_cfg: dict[str, Any]) -> dict[str, Any]:
    """单探针测活, 返回 {alive, latency_ms, protocol, ip, port}."""
    ip = proxy["ip"]
    port = proxy["port"]
    protocol = proxy.get("protocol", "http")
    proxies = build_proxy_dict(ip, port, protocol)

    t0 = time.time()
    try:
        r = requests.get(
            probe_cfg["url"],
            proxies=proxies,
            timeout=probe_cfg["timeout"],
            allow_redirects=False,
        )
        alive = r.status_code == probe_cfg["expect_status"]
    except Exception:
        alive = False

    return {
        "ip": ip,
        "port": port,
        "protocol": protocol,
        "source": proxy.get("source", ""),
        "alive": alive,
        "latency_ms": round((time.time() - t0) * 1000, 1),
    }


def verify_all(
    proxies: list[dict[str, Any]], probe_cfg: dict[str, Any], workers: int = 100
) -> list[dict[str, Any]]:
    """并发测活."""
    total = len(proxies)
    print(f"[2/4] 测活 {total} 个代理 ({workers} 并发, {probe_cfg['timeout']}s 超时)...", file=sys.stderr)

    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(probe_one, p, probe_cfg): p for p in proxies}
        done = 0
        for fut in as_completed(futs):
            r = fut.result()
            results.append(r)
            done += 1
            if done % 200 == 0 or done == total:
                alive_count = sum(1 for x in results if x["alive"])
                elapsed = time.time() - t_start
                rate = done / elapsed if elapsed > 0 else 0
                eta = (total - done) / rate if rate > 0 else 0
                print(
                    f"  [{done}/{total}] alive={alive_count} "
                    f"({rate:.0f}/s, ETA {eta:.0f}s)",
                    file=sys.stderr,
                )

    return results


def _aes_encrypt(plaintext: str, key: str) -> bytes:
    """AES-256-CBC 加密, 返回 iv + ciphertext 的二进制."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding
    except ImportError:
        # 没装 cryptography, 用 PyCryptodome
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        key_bytes = hashlib.sha256(key.encode()).digest()[:32]
        iv = os.urandom(16)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
        return iv + ct

    key_bytes = hashlib.sha256(key.encode()).digest()[:32]
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return iv + ct


def emit(results: list[dict[str, Any]]) -> None:
    """输出加密的 alive/http.enc, alive/socks5.enc, alive/meta.enc."""
    print("[3/4] 写入结果 (AES 加密)...", file=sys.stderr)

    aes_key = os.environ.get("PROXY_AES_KEY", "")
    if not aes_key:
        print("[FATAL] PROXY_AES_KEY 未设置, 无法加密", file=sys.stderr)
        sys.exit(1)

    alive_http = [r for r in results if r["alive"] and r["protocol"] == "http"]
    alive_socks5 = [r for r in results if r["alive"] and r["protocol"] == "socks5"]

    # 明文内容
    http_text = "\n".join(f"{r['ip']}:{r['port']}" for r in alive_http) + "\n" if alive_http else ""
    socks5_text = "\n".join(f"{r['ip']}:{r['port']}" for r in alive_socks5) + "\n" if alive_socks5 else ""

    meta = {
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_tested": len(results),
        "alive_http": len(alive_http),
        "alive_socks5": len(alive_socks5),
        "alive_total": len(alive_http) + len(alive_socks5),
        "hit_rate": f"{(len(alive_http) + len(alive_socks5)) / max(len(results), 1) * 100:.1f}%",
        "avg_latency_ms": round(
            sum(r["latency_ms"] for r in results if r["alive"])
            / max(len([r for r in results if r["alive"]]), 1),
            1,
        ),
        "sources": sorted(set(r.get("source", "") for r in results if r["alive"])),
    }
    meta_text = json.dumps(meta, indent=2, ensure_ascii=False)

    # 加密并写入 .enc 文件
    for name, text in [("http", http_text), ("socks5", socks5_text), ("meta", meta_text)]:
        encrypted = _aes_encrypt(text, aes_key)
        enc_path = ALIVE_DIR / f"{name}.enc"
        enc_path.write_bytes(encrypted)
        print(f"  alive/{name}.enc: {len(encrypted)} bytes", file=sys.stderr)

    # 同时写一份明文 meta.json 到本地 (不 commit, 仅供 Actions 日志查看)
    (ALIVE_DIR / "meta.json").write_text(meta_text, encoding="utf-8")

    print(
        f"  http: {len(alive_http)} 条, socks5: {len(alive_socks5)} 条\n"
        f"  meta: {json.dumps(meta, ensure_ascii=False)}",
        file=sys.stderr,
    )


def main() -> int:
    global t_start
    t_start = time.time()

    cfg = load_config()
    sources = cfg.get("sources", [])
    probe_cfg = cfg.get("probe", {
        "url": "https://www.google.com/generate_204",
        "expect_status": 204,
        "timeout": 4,
    })
    workers = cfg.get("workers", 100)

    if not sources:
        print("[FATAL] sources.json 无源", file=sys.stderr)
        return 2

    # 1. 拉取
    proxies = collect_all(sources)
    if not proxies:
        print("[FATAL] 未拉到任何代理", file=sys.stderr)
        return 2

    # 2. 测活
    results = verify_all(proxies, probe_cfg, workers)

    # 3. 输出
    emit(results)

    # 4. 汇总
    elapsed = time.time() - t_start
    alive = sum(1 for r in results if r["alive"])
    print(
        f"\n[4/4] 完成: {alive}/{len(results)} alive, 耗时 {elapsed:.0f}s",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
