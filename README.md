# SiteVitals

**Strumenti gratuiti e open source per controllare la salute e la sicurezza di un sito web e della tua rete di casa.**

SiteVitals è una suite in **Python puro** (solo libreria standard, nessuna installazione) che genera report chiari e leggibili. Due strumenti:

- **`sitevitals.py`** — *Report Sito*: dato un dominio, analizza CMS/stack, certificato TLS, security headers, file sensibili esposti, compliance cookie e navigabilità.
- **`netvitals.py`** — *Report Rete*: analizza la sicurezza della **tua rete di casa** (router/modem): porte e servizi in ascolto, identificazione del router, avviso su password di default, indicazioni firewall.

> ⚠️ **Uso consentito:** solo su domini e reti **di tua proprietà** o per cui hai **autorizzazione esplicita**. Scansionare sistemi altrui senza permesso è illegale (in Italia art. 615-ter c.p.). Questi strumenti sono **difensivi** (self-audit): non eseguono exploit.

---

## Requisiti

- **Python 3.8+** (su Windows si installa dal Microsoft Store o da [python.org](https://python.org))
- Nessun pacchetto esterno da installare.

## Uso

**Report Sito**
```bash
python sitevitals.py https://iltuosito.it
```
Genera `sitevitals_report.html` (aprilo nel browser).

**Report Rete (rete di casa)**
```bash
python netvitals.py
```
Genera `netvitals_report.html`.

Opzioni utili: `--out nome.html` per scegliere il file, `--max-pages N` (solo sito) per limitare le pagine.

---

## Cosa controlla

### Report Sito (`sitevitals.py`)
- CMS e stack tecnologico, con versioni esposte negli header
- Certificato TLS/HTTPS e scadenza
- Security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options…)
- File sensibili accessibili pubblicamente (`.env`, `.git/`, backup, `debug.log`…)
- Cookie impostati prima del consenso + banner/CMP + policy linkate
- Navigabilità: pagine, link rotti, 404, redirect

### Report Rete (`netvitals.py`)
- Rilevamento del router (gateway) e identificazione marca/modello
- Porte/servizi in ascolto su router e PC, con **spiegazione di cosa fa ogni servizio** e se conviene **tenerlo aperto o chiuderlo (e perché)**
- Avviso sulle **credenziali di default** note per la marca rilevata
- Indicazioni su firewall e gestione remota del router

---

## Roadmap

Il progetto è pensato in due fasi (dettagli in [`BLUEPRINT.md`](BLUEPRINT.md)):

- **Fase 1 — Questa repo (gratis, open source):** gli strumenti a riga di comando qui presenti.
- **Fase 2 — Web app SaaS:** gli stessi motori dietro un'interfaccia web, con account utente, cross-reference CVE, correzioni guidate a pagamento, report PDF e dashboard. (Progetto separato, non in questa repo.)

Contributi benvenuti: apri una *issue* o una *pull request*.

## Licenza

[MIT](LICENSE) — libero utilizzo, anche commerciale, con citazione della licenza.
