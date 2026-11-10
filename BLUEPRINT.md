# SiteVitals — Blueprint di progetto (v2)

> Documento di handoff per costruire **SiteVitals** fino al prodotto completo.
> Pensato anche per essere dato in pasto ad Antigravity o ad altri tool di sviluppo.

---

## 1. Visione

SiteVitals offre **due tipi di report**, a scelta dell'utente:

1. **Report Sito** — dato un dominio, audit di salute, sicurezza e compliance del sito web.
2. **Report Rete (privato)** — audit di sicurezza della **rete di casa/ufficio** dell'utente: router/modem, porte, servizi in ascolto, password di default, firewall.

Modello **freemium**: scansione gratuita (con limiti), **correzioni guidate a pagamento**.

> **Regola legale fondamentale:** scansioni consentite solo su domini/reti di proprietà dell'utente o autorizzati. Strumenti **difensivi** (self-audit), mai offensivi.

---

## 2. Nota di architettura (importante)

- Il **Report Sito** analizza un bersaglio pubblico (un dominio): può girare **lato server** (VPS) oppure in locale.
- Il **Report Rete** analizza la LAN privata dell'utente (router, dispositivi interni, porte interne): **non è raggiungibile da un server su internet** (è dietro il NAT). Deve quindi essere eseguito da uno **strumento locale** sul PC dell'utente.

Conseguenza pratica: lo strumento locale (Fase 1) copre **entrambi** i report; la web app a pagamento (Fase 2) copre pienamente il Report Sito e, per il Report Rete, offre in download lo strumento locale.

---

## 3. Le due fasi

### FASE 1 — Strumento locale gratuito (repo pubblica GitHub)
- Script Python puri, nessuna installazione: `sitevitals.py` (sito) + `netvitals.py` (rete).
- Output: report HTML leggibili.
- Scopo: utilità reale + acquisizione utenti + credibilità/portfolio open source.
- Licenza MIT. Contributi aperti.
- **Stato: realizzata (questa repo).**

### FASE 2 — Web app SaaS a pagamento (VPS + dominio Aruba)
- Gli stessi motori dietro un'interfaccia web, online, con monetizzazione.
- Hosting: VPS proprio; dominio registrato su **Aruba** che punta al server (record A → IP del VPS), HTTPS con certificato.
- Funzionalità aggiuntive rispetto alla Fase 1:
  - Scelta **Report Sito / Report Rete** (il Report Rete rimanda al download dello strumento locale).
  - **Account utente** + ruolo **superadmin**.
  - **Limiti freemium**: 3 scansioni/giorno; dalla 4ª, pubblicità (durata crescente) per sbloccarne una.
  - **Cross-reference CVE**: versione rilevata ↔ vulnerabilità note ↔ versione che le risolve.
  - **Correzioni guidate a pagamento**: €9,90 a sito, sblocca tutte le correzioni di quel sito.
  - **Procedura guidata** con avanzamento e, a fine flusso, pagamento **Stripe**.
  - **Report PDF** generato e **inviato via email** al cliente dopo il pagamento.
  - **Ri-scansione**: le vulnerabilità non corrette ricompaiono; quelle corrette (verificate) risultano risolte. Tracciamento per account/IP.
  - **Dashboard Superadmin**: KPI, log scansioni, vulnerabilità aggregate, correzioni vendute.
  - **Velocità del sito**: misura reale lato server (TTFB/tempi di risposta) mostrata con indicatori tipo tachimetro.

---

## 4. Report Rete — dettaglio del modulo

Lo strumento locale (`netvitals.py`, da ampliare) produce un report che include:
- **Router (gateway)**: IP, identificazione marca/modello.
- **Password di default**: avviso se la marca ha credenziali note; verifica che siano state cambiate.
- **Porte/servizi in ascolto** su router e PC: per ciascuno, **cosa fa il servizio**, **su quale porta ascolta**, **se conviene tenerlo aperto o chiuderlo e perché**.
- **Firewall**: stato e indicazioni (firewall di sistema, SPI del router, gestione remota WAN disattivata).
- **UPnP**: segnalazione se attivo (apre porte automaticamente).
- Ampliamenti futuri: scoperta dispositivi sulla LAN, controllo Wi-Fi (cifratura WPA2/WPA3), verifica automatica credenziali di default sul pannello del proprio router.

---

## 5. Stack tecnico (Fase 2)

- **Frontend:** React (o il prototipo HTML come base) — viste Scanner e Admin.
- **Backend/API:** Python (FastAPI) che riusa `sitevitals.py` come libreria del motore.
- **Scansione:** worker/coda (es. Celery/RQ) con timeout e rate-limit.
- **Database:** PostgreSQL.
- **Pagamenti:** Stripe (Checkout + webhook).
- **Email:** servizio transazionale (Resend/Postmark/SendGrid).
- **PDF:** generazione server-side (WeasyPrint/ReportLab).
- **Hosting:** VPS; dominio Aruba (record A → IP VPS); HTTPS (Let's Encrypt/Certbot).
- **Auth:** email/password + ruoli (user, superadmin); sessioni/JWT.

---

## 6. Schema database (bozza, Fase 2)

- **users** — id, email, password_hash, ruolo, created_at
- **sites** — id, user_id, dominio, verificato, metodo_verifica, created_at
- **scans** — id, site_id, user_id, ip, dominio, tipo (sito|rete), punteggio, stato, raw_json, created_at
- **vulnerabilities** — id, scan_id, tipo, gravità, posizione, descrizione, cve, versione_fix, risolta
- **purchases** — id, user_id, site_id, importo, valuta, stripe_session_id, stato, created_at
- **unlocks** — id, purchase_id, site_id, created_at
- **reports** — id, purchase_id, pdf_path, inviato_a, inviato_at
- **scan_quota** — id, identificatore (user_id o ip), data, conteggio

---

## 7. Verifica di proprietà del dominio (Fase 2)

Prima delle funzioni avanzate/correzioni su un dominio: verifica tramite **record DNS TXT** con token o **file di verifica** nella root (come Google Search Console).

---

## 8. API principali (bozza, Fase 2)

- `POST /api/scan` — avvia scansione (dominio, tipo). Rispetta quota. → scan_id
- `GET /api/scan/{id}` — stato + risultato JSON
- `POST /api/checkout` — crea sessione Stripe per sbloccare un sito
- `POST /api/stripe/webhook` — conferma pagamento → unlock → genera+invia PDF
- `GET /api/report/{purchase_id}.pdf` — scarica PDF (autorizzato)
- `GET /api/admin/overview` — KPI + log (solo superadmin)

---

## 9. Roadmap operativa (Fase 2)

1. **M1** — Motore come API (FastAPI che usa `sitevitals.py`) + salvataggio su DB.
2. **M2** — Auth + quota (login, ruoli, 3/giorno lato server + gate pubblicità crescente).
3. **M3** — Pagamento Stripe (checkout + webhook + sblocco per sito).
4. **M4** — PDF + email al cliente dopo pagamento.
5. **M5** — CVE + ri-scansione con verifica reale.
6. **M6** — Dashboard Superadmin con dati reali.
7. **M7** — Velocità sito reale (TTFB) + rifinitura Report Rete (download dello strumento locale dalla web app).
8. **M8 (opzionale)** — Correzioni automatiche via plugin WordPress/accesso server.

---

## 10. Note di sicurezza e legali

- Scansioni solo su asset di proprietà/autorizzati; registrare il consenso.
- Correzioni automatiche mai senza backup e conferma esplicita.
- Conservare in sicurezza chiavi Stripe/email ed eventuali accessi ai siti collegati.
- GDPR: informativa, base giuridica, conservazione limitata dei report e dei log.
