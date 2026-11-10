#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
net-lan — audit di sicurezza della TUA rete locale (modem/router di casa o ufficio).

Parte della suite net-repo. Usa solo la libreria standard di Python (nessuna
installazione). Esegue un controllo DIFENSIVO della rete a cui sei connesso:
individua il gateway (router), prova a identificarne marca/modello, verifica
quali porte sono in ascolto sul router e sul tuo PC, spiega cosa fa ogni
servizio e se conviene lasciarlo aperto o chiuderlo, e segnala se il router
rischia di avere credenziali di default.

USO CONSENTITO: esclusivamente sulla TUA rete e sui TUOI dispositivi, o su reti
per cui hai autorizzazione esplicita. Scansionare reti o dispositivi altrui
senza permesso è illegale (in Italia art. 615-ter c.p.).

    python3 net-lan.py
    python3 net-lan.py --out net-lan_report.html
"""

import argparse
import html
import socket
import subprocess
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor

TIMEOUT = 0.8

# porta -> (nome, descrizione, raccomandazione, gravità)
# gravità: ok | avviso | critico
PORTS = {
    21:  ("FTP", "Trasferimento file non cifrato.", "Chiudere: usa SFTP/FTPS. Le credenziali viaggiano in chiaro.", "critico"),
    22:  ("SSH", "Accesso remoto cifrato.", "Ok se ti serve e usi password forti o chiavi. Non esporre a internet se non necessario.", "ok"),
    23:  ("Telnet", "Accesso remoto NON cifrato.", "Chiudere subito: protocollo obsoleto e insicuro.", "critico"),
    25:  ("SMTP", "Invio email.", "Chiudere se non gestisci un mail server.", "avviso"),
    53:  ("DNS", "Risoluzione nomi.", "Normale sul router. Non esporre a internet (rischio DNS amplification).", "ok"),
    80:  ("HTTP", "Interfaccia web (spesso il pannello del router).", "Ok solo in LAN. Non deve essere raggiungibile da internet.", "avviso"),
    135: ("RPC", "Windows RPC.", "Chiudere verso internet: superficie d'attacco classica su Windows.", "avviso"),
    139: ("NetBIOS", "Condivisione file Windows (legacy).", "Chiudere verso internet.", "avviso"),
    443: ("HTTPS", "Interfaccia web cifrata.", "Ok. Se è il pannello del router, tienilo solo in LAN.", "ok"),
    445: ("SMB", "Condivisione file Windows.", "MAI esposto a internet (ransomware/worm lo sfruttano). Ok solo in LAN fidata.", "critico"),
    1900:("SSDP/UPnP", "Scoperta dispositivi UPnP.", "Valuta di disattivare UPnP sul router: spesso apre porte da solo.", "avviso"),
    3389:("RDP", "Desktop remoto Windows.", "Molto preso di mira. Non esporre a internet: usa una VPN.", "critico"),
    5000:("UPnP/HTTP", "Servizio UPnP o pannello web.", "Verifica cosa risponde; chiudi verso internet se non serve.", "avviso"),
    7547:("TR-069 (CWMP)", "Gestione remota del router da parte del provider.", "Se aperto verso internet è un rischio noto: verifica col provider.", "avviso"),
    8080:("HTTP-alt", "Pannello web alternativo/proxy.", "Chiudi verso internet se non necessario.", "avviso"),
    8443:("HTTPS-alt", "Pannello web cifrato alternativo.", "Ok solo in LAN; non esporre a internet.", "avviso"),
    9100:("Stampante", "Stampa diretta (JetDirect).", "Tieni solo in LAN.", "ok"),
}

# marche note -> stringhe da cercare nella pagina/header del router
ROUTER_FINGERPRINTS = {
    "TP-Link": ["tp-link", "tplink"],
    "FRITZ!Box (AVM)": ["fritz", "avm"],
    "Netgear": ["netgear"],
    "D-Link": ["d-link", "dlink"],
    "Asus": ["asus", "rt-"],
    "TIM/Technicolor": ["technicolor", "tim hub", "ag combo"],
    "Vodafone Station": ["vodafone"],
    "Fastweb": ["fastweb", "nexxt"],
    "Huawei": ["huawei"],
    "Linksys": ["linksys"],
    "Zyxel": ["zyxel"],
}

# credenziali di default note (solo per AVVISO: l'utente verifica/cambia)
DEFAULT_CREDS = {
    "TP-Link": "admin / admin",
    "Netgear": "admin / password",
    "D-Link": "admin / (vuota)",
    "Asus": "admin / admin",
    "Linksys": "admin / admin",
    "Zyxel": "admin / 1234",
}


def get_gateway():
    """Trova l'IP del router (default gateway) su Windows/Linux/macOS."""
    try:
        if sys.platform.startswith("win"):
            out = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                low = line.lower()
                if "gateway predefinito" in low or "default gateway" in low:
                    ip = line.split(":")[-1].strip()
                    if ip and ip[0].isdigit():
                        return ip
        else:
            out = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                if line.startswith("default"):
                    parts = line.split()
                    if "via" in parts:
                        return parts[parts.index("via") + 1]
    except Exception:
        pass
    return None


def scan_port(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        return port if s.connect_ex((host, port)) == 0 else None
    except Exception:
        return None
    finally:
        s.close()


def scan_host(host):
    open_ports = []
    with ThreadPoolExecutor(max_workers=40) as ex:
        for res in ex.map(lambda p: scan_port(host, p), PORTS.keys()):
            if res:
                open_ports.append(res)
    return sorted(open_ports)


def identify_router(gateway):
    """Legge la pagina/header del router per dedurne la marca."""
    for scheme in ("http", "https"):
        url = f"{scheme}://{gateway}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "net-repo-lan/0.1"})
            ctx = None
            if scheme == "https":
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=3, context=ctx) as r:
                body = r.read(40000).decode("utf-8", "replace").lower()
                server = (r.headers.get("server") or "").lower()
        except Exception:
            continue
        blob = server + " " + body
        for brand, needles in ROUTER_FINGERPRINTS.items():
            if any(n in blob for n in needles):
                return brand, server
        return "Sconosciuta", server
    return None, None


def esc(x):
    return html.escape(str(x))


def build_html(gateway, brand, server, gw_ports, local_ports, out):
    def rows(ports):
        if not ports:
            return "<tr><td colspan=4 class='ok'>Nessuna porta aperta rilevata ✔</td></tr>"
        r = ""
        for p in ports:
            name, desc, rec, sev = PORTS[p]
            cls = {"ok": "ok", "avviso": "warn", "critico": "bad"}[sev]
            r += (f"<tr><td><b>{p}</b> {esc(name)}</td><td>{esc(desc)}</td>"
                  f"<td class='{cls}'>{esc(rec)}</td></tr>")
        return r

    cred = DEFAULT_CREDS.get(brand)
    cred_html = (f"<p class='bad'>⚠️ Marca {esc(brand)}: credenziali di default note = <code>{esc(cred)}</code>. "
                 f"Verifica di averle cambiate!</p>" if cred else
                 "<p class='mut'>Cambia sempre la password di default del pannello del router.</p>")

    with open(out, "w", encoding="utf-8") as f:
        f.write(f"""<!DOCTYPE html><html lang='it'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>net-repo LAN — report rete</title><style>
body{{margin:0;font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0e1016;color:#e8eaef;line-height:1.5}}
header{{padding:24px 20px;background:linear-gradient(135deg,#12151c,#1b2130);border-bottom:1px solid #262b36}}
h1{{margin:0;font-size:21px}} .sub{{color:#9aa0aa;font-size:14px;margin-top:4px}}
main{{max-width:880px;margin:0 auto;padding:20px}}
.card{{background:#171b24;border:1px solid #262b36;border-radius:14px;padding:18px 20px;margin:16px 0}}
.card h2{{font-size:16px;margin:0 0 12px}}
table{{width:100%;border-collapse:collapse;font-size:13.5px}} td{{padding:8px;border-bottom:1px solid #262b36;vertical-align:top}}
.ok{{color:#36c46a}} .warn{{color:#f6ae2d}} .bad{{color:#f0444b}} .mut{{color:#9aa0aa}}
code{{background:#0b0d12;padding:2px 6px;border-radius:5px;font-size:12px;color:#9aa0aa}}
footer{{color:#9aa0aa;font-size:12px;text-align:center;padding:24px}}
</style></head><body>
<header><h1>🛡️ net-repo — Sicurezza della rete locale</h1>
<div class='sub'>Router: {esc(gateway or '?')} · {esc(brand or '?')} · {esc(server or '')}</div></header>
<main>
<div class='card'><h2>🔐 Pannello del router</h2>{cred_html}</div>
<div class='card'><h2>🔌 Porte/servizi sul router ({esc(gateway)})</h2>
<table><tr><td><b>Porta</b></td><td><b>Cosa fa</b></td><td><b>Raccomandazione</b></td></tr>{rows(gw_ports)}</table></div>
<div class='card'><h2>💻 Porte/servizi sul tuo PC (127.0.0.1)</h2>
<table><tr><td><b>Porta</b></td><td><b>Cosa fa</b></td><td><b>Raccomandazione</b></td></tr>{rows(local_ports)}</table></div>
<div class='card'><h2>🧱 Firewall</h2>
<p class='mut'>Verifica che il firewall sia attivo: Windows → "Sicurezza di Windows" → Firewall e protezione rete.
Sul router, controlla che il firewall/SPI sia abilitato e che la gestione remota (WAN) sia disattivata.</p></div>
</main>
<footer>net-repo 0.1 (LAN) — audit difensivo. Usare solo sulla propria rete o autorizzate.</footer>
</body></html>""")


def main():
    ap = argparse.ArgumentParser(description="net-repo (LAN) — audit della rete locale (solo rete propria).")
    ap.add_argument("--out", default="net-lan_report.html", help="file report HTML")
    args = ap.parse_args()

    print("\n  net-repo (LAN) — audit della TUA rete locale")
    print("  (usare solo sulla propria rete o su reti autorizzate)\n")

    gateway = get_gateway()
    if not gateway:
        print("  ✗ Impossibile determinare il router (gateway). Verifica di essere connesso a una rete.")
        sys.exit(1)
    print(f"  • Router (gateway): {gateway}")

    print("  • Identificazione marca/modello…")
    brand, server = identify_router(gateway)

    print("  • Scansione porte del router…")
    gw_ports = scan_host(gateway)

    print("  • Scansione porte del tuo PC…")
    local_ports = scan_host("127.0.0.1")

    build_html(gateway, brand, server, gw_ports, local_ports, args.out)
    print(f"\n  ✔ Report salvato in: {args.out}")
    if brand in DEFAULT_CREDS:
        print(f"  ⚠ Marca {brand}: controlla di aver cambiato la password di default!\n")
    else:
        print()


if __name__ == "__main__":
    main()
