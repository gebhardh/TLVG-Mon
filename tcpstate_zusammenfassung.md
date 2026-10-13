# TCP/IPv4-Stack & Connection-State-Tooling — Zusammenfassung

Arbeitsnotiz zum Dialog: Aufbau von Werkzeugen, die HTTP-Verbindungen gezielt in
einem wählbaren TCP-Zustand halten — für Resilienz-, Leak- und Timeout-Tests
gegen den **eigenen** nginx (1.24.0) inkl. Monitoring per Telegraf.

> Nur gegen Systeme einsetzen, für die eine Erlaubnis vorliegt.

---

## 1. Ausgangslage: TCP/IP-Stack mit IPv4

Kein eigenständiges „TCPv4“ — gemeint ist der TCP/IP-Stack mit **IPv4** als
Vermittlungsschicht. TCP hat keine Versionsnummer, IP schon (IPv4/IPv6).

| Schicht | Protokolle | Aufgabe |
|---|---|---|
| Anwendung | HTTP, DNS, SMTP, SSH | Anwendungsdaten |
| Transport | **TCP**, UDP | Ende-zu-Ende zwischen Prozessen (Ports) |
| Internet | **IPv4**, ICMP, ARP | Adressierung, Routing zwischen Hosts |
| Netzzugang | Ethernet, WLAN | Übertragung im lokalen Segment (MAC) |

**TCP-Kern:** verbindungsorientiert (3-Way-Handshake SYN → SYN/ACK → ACK),
zuverlässig (Seq/Ack, Retransmission), Fluss- und Staukontrolle, Zustandsautomat
(LISTEN, SYN_SENT, ESTABLISHED, FIN_WAIT, CLOSE_WAIT, TIME_WAIT …).

---

## 2. Ziel: Session in einem Zustand „parken“

Anforderung: eine HTTP-Verbindung aufbauen und **in genau dem per CLI
übergebenen TCP-Zustand hängen lassen**, ohne weiter voranzuschreiten.

Zentrale Einsicht: Mit normalen OS-Sockets lässt sich der Zustand **nicht frei
wählen** — den Automaten steuert der Kernel. Zwei Wege:

- **Raw/scapy** (Zustandsautomat selbst fahren) → jeder Zustand frei wählbar,
  aber root nötig und Kernel-RST muss unterdrückt werden.
- **OS-Sockets (asyncio)** → nur „natürliche“ Zustände, dafür leichtgewichtig,
  skaliert auf tausende Verbindungen, Zustände auch clientseitig sichtbar.

---

## 3. Werkzeug A — `tcpstate.py` (raw / scapy)

Fährt den TCP-Zustandsautomaten selbst per raw packets und hält in einem
beliebigen Zustand. User-Space, aber privilegiert (`CAP_NET_RAW` / root).

**Unterstützte Zustände:**

| Zustand | Erreicht durch |
|---|---|
| `SYN_SENT` | SYN raus, kein ACK |
| `ESTABLISHED` | Handshake fertig, offen gehalten (Keep-Alive-Probes) |
| `FIN_WAIT_1` | eigenes FIN raus, dessen ACK ignoriert |
| `FIN_WAIT_2` | FIN bestätigt, Gegen-FIN ignoriert |
| `TIME_WAIT` | vollständig aktiv geschlossen, 2·MSL halten |
| `CLOSE_WAIT` | Server schließt (`Connection: close`), eigenes FIN zurückgehalten |
| `LAST_ACK` | aus CLOSE_WAIT eigenes FIN raus, finales ACK ignoriert |

**Zwei Fallstricke:**

- **root nötig** (raw sockets).
- **Kernel-RST:** Der Kernel kennt die scapy-Verbindung nicht und killt sie beim
  SYN-ACK mit RST. Lösung — ausgehendes RST auf den Quellports droppen
  (`--setup-firewall` setzt/entfernt die Regel automatisch für den Portbereich):

  ```bash
  sudo iptables -A OUTPUT -p tcp --sport <LO>:<HI> --tcp-flags RST RST -j DROP
  ```

**Mehrere Verbindungen** über `-n/--count` (je eigener Thread + Quellport),
`--sport-base`, `--ramp`.

```bash
sudo python3 tcpstate.py 10.0.0.5 -s CLOSE_WAIT -n 50 --ramp 0.1 --setup-firewall
sudo python3 tcpstate.py 10.0.0.5 -s ESTABLISHED -n 20 -t 0 --setup-firewall
```

**Grenzen:** scapy skaliert schlecht (Sniff-Thread pro Verbindung → Client wird
ab einigen Hundert selbst zum Flaschenhals).

---

## 4. Werkzeug B — `tcpstate_async.py` (asyncio / OS-Sockets)

Echte Kernel-Sockets, kein root, skaliert auf tausende Verbindungen auf einem
Kern. Zustände sind damit **auch clientseitig** im Socket-Table sichtbar.

**Erreichbare Zustände:** `ESTABLISHED`, `CLOSE_WAIT`, `FIN_WAIT`
(kernel-getimed, nur kurz beobachtbar).

```bash
# idle-offen -> worker_connections / keepalive_timeout
python3 tcpstate_async.py 10.0.0.5 -s ESTABLISHED -n 1000 --ramp 0.005 -t 0

# CLOSE_WAIT -> FD-/Connection-Leaks
python3 tcpstate_async.py 10.0.0.5 -s CLOSE_WAIT -n 500 --ramp 0.01

# unvollständige Header -> client_header_timeout
python3 tcpstate_async.py 10.0.0.5 -s ESTABLISHED -n 200 --partial -t 120
```

Optionen: `--http`, `--partial`, `--keepalive` (SO_KEEPALIVE), `--ramp`,
`--stats-interval` (Statuszeile mit `aktiv/erreicht/fehlgeschlagen`).

---

## 5. Monitoring-Thema: Telegraf meldet `tcp_none`

Telegraf liest die TCP-Zustände aus der **Socket-Tabelle des Kernels**
(`/proc/net/tcp`), nicht vom Draht. Pro Zustand ein Feld
(`tcp_established`, `tcp_close_wait` …); `tcp_none` sammelt Sockets ohne
TCP-Zustand (UDP, **Raw Sockets**).

- **Bei Werkzeug A** kennt der lokale Kernel die Verbindung nicht — nur scapys
  Raw-Socket taucht auf → clientseitig `tcp_none`. Der geparkte Zustand ist
  **serverseitig** sichtbar (dort existiert ein echter Socket).
- **Bei Werkzeug B** sind es echte Sockets → Zustände auch **clientseitig**
  zählbar; der `tcp_none`-Punkt ist damit gelöst.

Gegenprobe: `ss -tan` zeigt bei Werkzeug A clientseitig nichts im Zielzustand.

---

## 6. nginx 1.24.0 — worauf die Tests zielen

- **`worker_connections`** (× `worker_processes`): Budget gleichzeitiger
  Verbindungen; idle-ESTABLISHED frisst es, danach werden neue abgelehnt.
- **`keepalive_timeout`** (Default 75s): schließt idle keepalive-Verbindungen.
- **`client_header_timeout`** (Default 60s): schließt Verbindungen mit
  unvollständigem Header (`--partial`) — gewünschtes Schutzverhalten.
- **CLOSE_WAIT-Leak-Test:** dauerhaft steigende CLOSE_WAIT-Zahl = echtes Leak
  (App/Upstream). `worker_rlimit_nofile` und OS-FD-Limit prüfen.
- **`limit_conn` / `limit_conn_zone`:** Verbindungen pro IP begrenzen;
  zeigt, ob Schutzregeln greifen.

**Beobachten:**

```bash
# Server: Zustände zählen
watch -n1 "ss -tan | awk '{print \$1}' | sort | uniq -c"
ss -tan state close-wait | wc -l          # Leak-Indikator

# nginx stub_status (für Telegraf nginx-Input):
#   location /nginx_status { stub_status; allow 127.0.0.1; deny all; }
```

Telegraf: serverseitig **`nginx`**-Input (gegen `stub_status`) als Hauptquelle,
**`netstat`**-Input ergänzt die TCP-Zustandszähler; clientseitig
`netstat`-Input für die eigenen `tcp_established` / `tcp_close_wait`.

**Dimensionierung:** klein mit `-n` starten und steigern; vorher Client-FD-Limit
hochsetzen (`ulimit -n`), sonst limitiert der Client vor dem Server.

---

## 7. Dateien

| Datei | Zweck |
|---|---|
| `tcpstate.py` | raw/scapy — beliebiger TCP-Zustand, root + iptables nötig |
| `tcpstate_async.py` | asyncio/OS-Sockets — natürliche Zustände, skaliert, kein root |

## 8. Offene Punkte / mögliche nächste Schritte

- Konkrete Schwellwerte und Telegraf-Alerts aus der tatsächlichen nginx-Config
  ableiten (`worker_connections`, `keepalive_timeout`, Upstream/Proxy).
- Bei Bedarf serverseitige Zustände `SYN_RECEIVED` / `CLOSING` ergänzen.
