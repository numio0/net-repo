# net-repo

**Strumenti gratuiti e open source per controllare la salute e la sicurezza di un sito web e della tua rete locale.**

net-repo è una suite in **Python puro** (solo libreria standard, nessuna installazione) che genera report chiari e leggibili. Due strumenti:

- **`net-repo.py`** — *Report Sito*: dato un dominio, analizza CMS/stack, certificato TLS, security headers, file sensibili esposti, compliance cookie e navigabilità.
- **`net-lan.py`** — *Report Rete*: analizza la sicurezza della **tua rete locale** (router/modem): porte e servizi in ascolto, identificazione del router, avviso su password di default, indicazioni firewall.

> ⚠️ **Uso consentito:** solo su domini e reti **di tua proprietà** o per cui hai **autorizzazione esplicita**. Scansionare sistemi altrui senza permesso è illegale (in Italia art. 615-ter c.p.). Questi strumenti sono **difensivi** (self-audit): non eseguono exploit.

---

## Requisiti

- **Python 3.8+** (su Windows si installa dal Microsoft Store o da [python.org](https://python.org))
- Nessun pacchetto esterno da installare (funziona con la standard library).

## Uso

### 1. Report Sito (`net-repo.py`)
```bash
python net-repo.py https://iltuosito.it
```
Genera `net-repo_report.html` (aprilo direttamente nel browser).

Opzioni utili:
- `--out report.html`: specifica il nome del file di output.
- `--max-pages 40`: imposta il limite massimo di pagine scansionate (default: 25).

### 2. Report Rete Locale (`net-lan.py`)
```bash
python net-lan.py
```
Genera `net-lan_report.html`.

Opzioni utili:
- `--out report_rete.html`: specifica il nome del file di output.

---

## Cosa controlla

### Report Sito (`net-repo.py`)
- **CMS e stack tecnologico**: versioni esposte negli header (`X-Powered-By`, `Server`, meta generator, CMS come WordPress, Drupal, Joomla, Shopify, PrestaShop).
- **Certificato TLS/HTTPS**: versione TLS, data di scadenza e conteggio giorni rimanenti, emittente.
- **Security headers**: verifica HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- **File sensibili esposti**: controllo percorsi critici (`.env`, `.git/`, backup SQL, file di configurazione, `debug.log`, ecc.).
- **Compliance cookie e privacy**: rilevamento cookie impostati prima del consenso, banner/CMP (Cookiebot, Iubenda, CookieYes, OneTrust, ecc.), link a Privacy Policy e Cookie Policy.
- **Navigabilità del sito**: crawler interno passivo, codici di risposta HTTP, individuazione link rotti ed errori.

### Report Rete (`net-lan.py`)
- **Rilevamento router (gateway)** e identificazione marca/modello (TP-Link, FRITZ!Box, Netgear, D-Link, Asus, TIM, Vodafone, Fastweb, ecc.).
- **Porte e servizi in ascolto** su router e PC locale, con spiegazione dettagliata del servizio e raccomandazione se tenerlo aperto o chiuderlo.
- **Avviso credenziali di default** per marche note con password predefinite a rischio.
- **Indicazioni di hardening**: stato del firewall di sistema, SPI e disattivazione gestione remota WAN.

---

## Roadmap

Il progetto è strutturato in due fasi:

- **Fase 1 — Questa repo (gratuita, open source):** strumenti da riga di comando autonomi e leggeri.
- **Fase 2 — Web app SaaS:** piattaforma centralizzata con interfaccia web, account utente, cross-reference CVE automatico, correzioni guidate, generazione report PDF e dashboard superadmin.

Contributi benvenuti: apri una *issue* o una *pull request*.

---

## Licenza

Distribuito sotto licenza [MIT](LICENSE) — libero utilizzo, anche commerciale, con attribuzione.
