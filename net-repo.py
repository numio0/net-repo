#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
net-repo — scanner passivo di salute, sicurezza e compliance per siti web.

Usa SOLO la libreria standard di Python (nessun pip, nessuna installazione).
Esegue solo richieste HTTP/HTTPS passive (GET/HEAD) + lettura certificato TLS.
NON esegue exploit, NON fa scansioni di porte, NON tocca servizi di rete.

USO CONSENTITO: esclusivamente su domini di tua proprietà o per cui hai
autorizzazione scritta. La scansione di infrastruttura altrui senza permesso
può costituire reato (in Italia art. 615-ter c.p.).

    python3 net-repo.py https://tuodominio.it
    python3 net-repo.py https://tuodominio.it --max-pages 40 --out report.html
"""

import argparse
import datetime
import html
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from html.parser import HTMLParser

UA = "net-repo/0.1 (+self-audit)"
TIMEOUT = 12

# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def fetch(url, method="GET", max_bytes=600_000):
    """Scarica una URL. Ritorna dict con status, headers, body, url finale."""
    req = urllib.request.Request(url, method=method, headers={"User-Agent": UA})
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            raw = r.read(max_bytes) if method == "GET" else b""
            return {
                "ok": True,
                "status": r.status,
                "headers": {k.lower(): v for k, v in r.headers.items()},
                "body": raw.decode("utf-8", "replace"),
                "final_url": r.geturl(),
                "error": None,
            }
    except urllib.error.HTTPError as e:
        return {"ok": True, "status": e.code,
                "headers": {k.lower(): v for k, v in (e.headers or {}).items()},
                "body": "", "final_url": url, "error": None}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "status": None, "headers": {}, "body": "",
                "final_url": url, "error": str(e)}


# ---------------------------------------------------------------------------
# Parser per link, generator, script
# ---------------------------------------------------------------------------

class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.generator = None
        self.scripts = []
        self.title = None
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "meta" and a.get("name", "").lower() == "generator":
            self.generator = a.get("content")
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title and not self.title:
            self.title = data.strip()


def parse_page(body):
    p = PageParser()
    try:
        p.feed(body)
    except Exception:  # noqa: BLE001
        pass
    return p


# ---------------------------------------------------------------------------
# Moduli di analisi
# ---------------------------------------------------------------------------

def detect_stack(headers, body, generator):
    findings = []
    server = headers.get("server")
    powered = headers.get("x-powered-by")
    if server:
        findings.append(("Server", server))
    if powered:
        findings.append(("X-Powered-By (versione esposta)", powered))
    if generator:
        findings.append(("Meta generator", generator))

    cms = None
    b = body.lower()
    if "wp-content" in b or "wp-json" in b or (generator and "wordpress" in generator.lower()):
        cms = "WordPress"
    elif "woocommerce" in b:
        cms = "WordPress + WooCommerce"
    elif "/sites/all/" in b or (generator and "drupal" in generator.lower()):
        cms = "Drupal"
    elif "joomla" in b or (generator and "joomla" in generator.lower()):
        cms = "Joomla"
    elif "cdn.shopify.com" in b or "shopify" in b:
        cms = "Shopify"
    elif "x-powered-by" in headers and "prestashop" in b:
        cms = "PrestaShop"
    if cms:
        findings.append(("CMS rilevato", cms))
    return findings, cms


SECURITY_HEADERS = {
    "strict-transport-security": "HSTS (forza HTTPS)",
    "content-security-policy": "Content-Security-Policy (anti-XSS/iniezioni)",
    "x-frame-options": "X-Frame-Options (anti-clickjacking)",
    "x-content-type-options": "X-Content-Type-Options (anti-MIME-sniffing)",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def check_security_headers(headers):
    present, missing = [], []
    for key, desc in SECURITY_HEADERS.items():
        (present if key in headers else missing).append(desc)
    return present, missing


def check_tls(hostname):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
        not_after = cert.get("notAfter")
        exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days = (exp - datetime.datetime.utcnow()).days
        issuer = dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "?")
        return {"ok": True, "version": version, "days_left": days,
                "expires": not_after, "issuer": issuer}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


SENSITIVE_PATHS = [
    ".env", ".git/config", ".git/HEAD", "wp-config.php.bak", "wp-config.php~",
    "config.php.bak", "backup.sql", "database.sql", "dump.sql",
    ".DS_Store", "phpinfo.php", "info.php", ".htaccess.bak",
    "composer.json", "composer.lock", "package.json", ".svn/entries",
    "wp-content/debug.log",
]


def check_exposed_files(base):
    hits = []
    for path in SENSITIVE_PATHS:
        url = urllib.parse.urljoin(base, path)
        r = fetch(url, method="GET", max_bytes=2048)
        if r["ok"] and r["status"] == 200 and r["body"].strip():
            snippet = r["body"][:120].replace("\n", " ")
            hits.append((path, snippet))
    return hits


KNOWN_CMP = {
    "cookiebot": "Cookiebot", "iubenda": "Iubenda", "cookieyes": "CookieYes",
    "onetrust": "OneTrust", "usercentrics": "Usercentrics",
    "complianz": "Complianz", "cookie-law-info": "CookieYes/GDPR Cookie Consent",
    "borlabs": "Borlabs Cookie",
}


def check_compliance(headers, body, links):
    out = {}
    # Cookie impostati al primo caricamento (prima del consenso)
    set_cookie = headers.get("set-cookie")
    out["cookies_prima_consenso"] = set_cookie if set_cookie else None
    # CMP / banner cookie
    b = body.lower()
    cmp_found = [name for key, name in KNOWN_CMP.items() if key in b]
    out["cmp"] = sorted(set(cmp_found))
    # Link a policy
    txt = b
    out["privacy_policy"] = any("privacy" in l.lower() for l in links) or "privacy policy" in txt
    out["cookie_policy"] = any("cookie" in l.lower() for l in links) or "cookie policy" in txt
    return out


def crawl(base, max_pages):
    host = urllib.parse.urlparse(base).netloc
    seen, results = set(), []
    q = deque([base])
    while q and len(results) < max_pages:
        url = q.popleft()
        norm = url.split("#")[0].rstrip("/")
        if norm in seen:
            continue
        seen.add(norm)
        r = fetch(url, method="GET")
        status = r["status"] if r["ok"] else "ERR"
        results.append((url, status, r.get("error")))
        if r["ok"] and r["status"] == 200 and r["body"]:
            for href in parse_page(r["body"]).links:
                full = urllib.parse.urljoin(url, href)
                p = urllib.parse.urlparse(full)
                if p.netloc == host and p.scheme in ("http", "https"):
                    clean = full.split("#")[0].rstrip("/")
                    if clean not in seen:
                        q.append(full)
    return results


# ---------------------------------------------------------------------------
# Report HTML
# ---------------------------------------------------------------------------

def esc(x):
    return html.escape(str(x))


def build_report(target, data):
    now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    broken = [r for r in data["crawl"] if r[1] not in (200, 301, 302)]
    rows_headers_missing = "".join(f"<li class='bad'>{esc(d)}</li>" for d in data["sec_missing"])
    rows_headers_present = "".join(f"<li class='ok'>{esc(d)}</li>" for d in data["sec_present"])
    stack_rows = "".join(f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>" for k, v in data["stack"])
    exposed_rows = "".join(
        f"<tr><td class='bad'>{esc(p)}</td><td><code>{esc(s)}</code></td></tr>"
        for p, s in data["exposed"]) or "<tr><td colspan=2 class='ok'>Nessun file sensibile accessibile pubblicamente ✔</td></tr>"
    crawl_rows = "".join(
        f"<tr><td>{esc(u)}</td><td class='{'bad' if s not in (200,301,302) else 'ok'}'>{esc(s)}</td></tr>"
        for u, s, _ in data["crawl"])

    tls = data["tls"]
    if tls["ok"]:
        tls_cls = "bad" if tls["days_left"] < 15 else "ok"
        tls_html = (f"<p class='{tls_cls}'>TLS {esc(tls['version'])} · scade tra "
                    f"<b>{tls['days_left']} giorni</b> ({esc(tls['expires'])}) · "
                    f"emesso da {esc(tls['issuer'])}</p>")
    else:
        tls_html = f"<p class='bad'>Impossibile leggere il certificato: {esc(tls['error'])}</p>"

    comp = data["compliance"]
    comp_cookie = "<span class='bad'>Sì — cookie impostati PRIMA del consenso ⚠</span>" if comp["cookies_prima_consenso"] else "<span class='ok'>No ✔</span>"
    comp_cmp = ", ".join(comp["cmp"]) if comp["cmp"] else "<span class='warn'>Nessun banner cookie noto rilevato ⚠</span>"

    return f"""<!DOCTYPE html>
<html lang="it"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>net-repo — {esc(target)}</title>
<style>
  :root{{--bg:#0f1115;--card:#1a1d24;--txt:#e6e8ec;--mut:#9aa0aa;--ok:#38b000;--bad:#e5383b;--warn:#f6ae2d;--acc:#4895ef}}
  *{{box-sizing:border-box}} body{{margin:0;font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--txt);line-height:1.5}}
  header{{padding:28px 20px;background:linear-gradient(135deg,#12151c,#1b2130);border-bottom:1px solid #262b36}}
  h1{{margin:0;font-size:22px}} .sub{{color:var(--mut);font-size:14px;margin-top:4px}}
  main{{max-width:900px;margin:0 auto;padding:20px}}
  .card{{background:var(--card);border:1px solid #262b36;border-radius:14px;padding:18px 20px;margin:16px 0}}
  .card h2{{font-size:16px;margin:0 0 12px;display:flex;align-items:center;gap:8px}}
  table{{width:100%;border-collapse:collapse;font-size:14px}} td{{padding:7px 8px;border-bottom:1px solid #262b36;vertical-align:top;word-break:break-all}}
  ul{{margin:6px 0;padding-left:20px;font-size:14px}}
  .ok{{color:var(--ok)}} .bad{{color:var(--bad)}} .warn{{color:var(--warn)}}
  code{{background:#0c0e12;padding:2px 5px;border-radius:5px;font-size:12px;color:var(--mut)}}
  .pill{{font-size:12px;padding:2px 9px;border-radius:999px;background:#0c0e12;color:var(--mut)}}
  footer{{color:var(--mut);font-size:12px;text-align:center;padding:24px}}
</style></head><body>
<header>
  <h1>🩺 net-repo — Report di salute</h1>
  <div class="sub">{esc(target)} · generato il {now}</div>
</header>
<main>
  <div class="card"><h2>🔧 Stack tecnologico</h2>
    <table>{stack_rows or "<tr><td>Nessun dato rilevato</td></tr>"}</table>
    <p class="sub">Nota: le versioni esposte negli header (X-Powered-By, Server) andrebbero nascoste.</p>
  </div>

  <div class="card"><h2>🔐 Certificato TLS / HTTPS</h2>{tls_html}</div>

  <div class="card"><h2>🛡️ Security headers</h2>
    <b class="ok">Presenti</b><ul>{rows_headers_present or "<li class='warn'>Nessuno</li>"}</ul>
    <b class="bad">Mancanti</b><ul>{rows_headers_missing or "<li class='ok'>Nessuno — tutti presenti ✔</li>"}</ul>
  </div>

  <div class="card"><h2>📁 File sensibili esposti</h2>
    <table><tr><td><b>Percorso</b></td><td><b>Anteprima</b></td></tr>{exposed_rows}</table>
  </div>

  <div class="card"><h2>🍪 Compliance cookie / privacy</h2>
    <table>
      <tr><td>Cookie prima del consenso</td><td>{comp_cookie}</td></tr>
      <tr><td>Banner cookie (CMP)</td><td>{comp_cmp}</td></tr>
      <tr><td>Privacy policy linkata</td><td>{"<span class='ok'>Sì ✔</span>" if comp['privacy_policy'] else "<span class='bad'>Non trovata ⚠</span>"}</td></tr>
      <tr><td>Cookie policy linkata</td><td>{"<span class='ok'>Sì ✔</span>" if comp['cookie_policy'] else "<span class='bad'>Non trovata ⚠</span>"}</td></tr>
    </table>
    <p class="sub">La valutazione legale completa (GDPR, EEA, NIS2, DORA) richiede un questionario sul fatturato e sul tipo di attività — modulo separato.</p>
  </div>

  <div class="card"><h2>🧭 Navigabilità — {len(data['crawl'])} pagine · <span class="{'bad' if broken else 'ok'}">{len(broken)} problemi</span></h2>
    <table><tr><td><b>URL</b></td><td><b>Stato</b></td></tr>{crawl_rows}</table>
  </div>
</main>
<footer>net-repo 0.1 — scanner passivo. Usare solo su domini propri o autorizzati.</footer>
</body></html>"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="net-repo — audit passivo di un sito web.")
    ap.add_argument("url", help="URL del dominio (es. https://tuodominio.it)")
    ap.add_argument("--max-pages", type=int, default=25, help="pagine max da controllare")
    ap.add_argument("--out", default="net-repo_report.html", help="file report HTML")
    args = ap.parse_args()

    target = args.url if args.url.startswith("http") else "https://" + args.url
    host = urllib.parse.urlparse(target).netloc

    print(f"\n  net-repo — scansione di {target}")
    print("  (solo su domini di tua proprietà o autorizzati)\n")

    home = fetch(target)
    if not home["ok"]:
        print(f"  ✗ Impossibile raggiungere il sito: {home['error']}")
        sys.exit(1)
    target = home["final_url"]
    host = urllib.parse.urlparse(target).netloc
    page = parse_page(home["body"])

    print("  • Stack tecnologico…")
    stack, _ = detect_stack(home["headers"], home["body"], page.generator)
    print("  • Security headers…")
    sec_present, sec_missing = check_security_headers(home["headers"])
    print("  • Certificato TLS…")
    tls = check_tls(host)
    print("  • File sensibili esposti…")
    exposed = check_exposed_files(target)
    print("  • Compliance cookie/privacy…")
    compliance = check_compliance(home["headers"], home["body"], page.links)
    print(f"  • Navigabilità (max {args.max_pages} pagine)…")
    crawl_res = crawl(target, args.max_pages)

    data = {"stack": stack, "sec_present": sec_present, "sec_missing": sec_missing,
            "tls": tls, "exposed": exposed, "compliance": compliance, "crawl": crawl_res}

    with open(args.out, "w", encoding="utf-8") as f:
        f.write(build_report(target, data))

    print(f"\n  ✔ Report salvato in: {args.out}\n")


if __name__ == "__main__":
    main()
