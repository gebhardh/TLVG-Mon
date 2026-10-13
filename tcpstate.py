#!/usr/bin/env python3
"""tcpstate — hält eine oder mehrere TCP/HTTP-Verbindungen in einem wählbaren
TCP-Zustand.

User-Space-Tool. Der TCP-Zustandsautomat wird selbst gefahren (raw packets via
scapy), damit jede Verbindung in genau dem per --state übergebenen Zustand
"geparkt" werden kann, statt vom Kernel weitergeschaltet zu werden.

Einsatzzweck: Timeout-, Leak- und Resilienz-Tests gegen EIGENE Server/Proxies
(wie viele Clients in CLOSE_WAIT/FIN_WAIT verträgt der Server, bevor FDs oder
der Connection-Pool auslaufen?) sowie zum Lernen des TCP-Zustandsautomaten.
Nur gegen Systeme einsetzen, für die du die Erlaubnis hast.

Voraussetzungen:
    pip install scapy
    root bzw. CAP_NET_RAW (raw sockets laufen im User-Space, aber privilegiert)

Der Kernel kennt die von scapy erzeugten Verbindungen nicht und schickt auf die
einlaufenden SYN-ACKs je ein RST, das die Session killt. Darum MUSS ausgehendes
RST auf den Quellports gedroppt werden (--setup-firewall macht das automatisch
für den gesamten genutzten Portbereich und räumt beim Beenden auf):

    sudo iptables -A OUTPUT -p tcp --sport <LO>:<HI> --tcp-flags RST RST -j DROP

Hinweis: Jede Verbindung läuft als eigener Thread mit eigenem Sniffer. Das ist
pro Verbindung teuer; für hohe --count-Werte ist eine socket-basierte Variante
geeigneter.
"""

import argparse
import atexit
import os
import random
import subprocess
import sys
import threading
import time

try:
    from scapy.all import IP, TCP, Raw, send, sniff, conf
except ImportError:
    sys.exit("scapy fehlt:  pip install scapy")

conf.verb = 0

ACTIVE_STATES = ["SYN_SENT", "ESTABLISHED", "FIN_WAIT_1", "FIN_WAIT_2", "TIME_WAIT"]
PASSIVE_STATES = ["CLOSE_WAIT", "LAST_ACK"]   # Server muss schließen
STATES = ACTIVE_STATES + PASSIVE_STATES

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

_print_lock = threading.Lock()
_stop = threading.Event()


def log(cid, msg):
    with _print_lock:
        print(f"[{cid:>3}] {msg}")


class Session:
    def __init__(self, cid, dst, dport, sport):
        self.cid = cid
        self.dst = dst
        self.dport = dport
        self.sport = sport
        self.seq = random.randint(0, 2**32 - 1)
        self.ack = 0

    def _ip(self):
        return IP(dst=self.dst)

    def _send(self, flags, payload=b""):
        pkt = self._ip() / TCP(sport=self.sport, dport=self.dport,
                               flags=flags, seq=self.seq, ack=self.ack,
                               window=65535)
        if payload:
            pkt = pkt / Raw(load=payload)
        send(pkt)

    def _recv(self, timeout=5):
        bpf = (f"tcp and src host {self.dst} and src port {self.dport} "
               f"and dst port {self.sport}")
        pkts = sniff(filter=bpf, timeout=timeout, count=1)
        return pkts[0] if pkts else None

    @staticmethod
    def _flags(pkt):
        return int(pkt[TCP].flags)

    def send_syn(self):
        self._send(SYN)
        self.seq += 1

    def recv_synack(self, timeout=5):
        pkt = self._recv(timeout)
        if pkt is None:
            raise TimeoutError("keine SYN-ACK erhalten")
        f = self._flags(pkt)
        if f & RST:
            raise ConnectionRefusedError("RST vom Server (Port zu?)")
        if not (f & SYN and f & ACK):
            raise RuntimeError(f"unerwartete Flags: {pkt[TCP].flags}")
        self.ack = pkt[TCP].seq + 1
        return pkt

    def send_ack(self):
        self._send(ACK)

    def send_http(self, host, method, path, connection):
        req = (f"{method} {path} HTTP/1.1\r\n"
               f"Host: {host}\r\nUser-Agent: tcpstate\r\n"
               f"Connection: {connection}\r\n\r\n").encode()
        self._send(PSH | ACK, req)
        self.seq += len(req)

    def send_fin(self):
        self._send(FIN | ACK)
        self.seq += 1

    def drain_until_fin(self, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline and not _stop.is_set():
            pkt = self._recv(timeout=max(0.5, deadline - time.time()))
            if pkt is None:
                continue
            payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
            f = self._flags(pkt)
            self.ack = pkt[TCP].seq + len(payload) + (1 if f & FIN else 0)
            if payload or (f & FIN):
                self._send(ACK)
            if f & FIN:
                return True
        return False


def park(sess, state, hold, keepalive=15):
    end = None if hold == 0 else time.time() + hold
    last = 0
    while (end is None or time.time() < end) and not _stop.is_set():
        if state == "ESTABLISHED" and time.time() - last > keepalive:
            pkt = sess._ip() / TCP(sport=sess.sport, dport=sess.dport,
                                   flags=ACK, seq=sess.seq - 1, ack=sess.ack)
            send(pkt)
            last = time.time()
        time.sleep(0.5)


def run_session(cid, args, sport, reached):
    """Eine Verbindung zum Zielzustand fahren und dort parken."""
    sess = Session(cid, args.host, args.port, sport)
    target = args.state
    passive = target in PASSIVE_STATES
    connection = "close" if passive or target in ("FIN_WAIT_1", "FIN_WAIT_2",
                                                  "TIME_WAIT") else "keep-alive"
    try:
        sess.send_syn()
        if target == "SYN_SENT":
            reached.release(); log(cid, f"SYN_SENT (sport={sport})")
            park(sess, "SYN_SENT", args.hold); return

        sess.recv_synack()
        sess.send_ack()

        if target == "ESTABLISHED":
            if args.http:
                sess.send_http(args.host, args.method, args.path, "keep-alive")
            reached.release(); log(cid, f"ESTABLISHED (sport={sport})")
            park(sess, "ESTABLISHED", args.hold); return

        if args.http or passive:
            sess.send_http(args.host, args.method, args.path, connection)

        if passive:
            sess.drain_until_fin(timeout=args.recv_timeout)
            if target == "CLOSE_WAIT":
                reached.release(); log(cid, f"CLOSE_WAIT (sport={sport})")
                park(sess, "CLOSE_WAIT", args.hold); return
            sess.send_fin()
            reached.release(); log(cid, f"LAST_ACK (sport={sport})")
            park(sess, "LAST_ACK", args.hold); return

        sess.send_fin()
        if target == "FIN_WAIT_1":
            reached.release(); log(cid, f"FIN_WAIT_1 (sport={sport})")
            park(sess, "FIN_WAIT_1", args.hold); return

        sess._recv(timeout=args.recv_timeout)   # ACK auf unser FIN
        if target == "FIN_WAIT_2":
            reached.release(); log(cid, f"FIN_WAIT_2 (sport={sport})")
            park(sess, "FIN_WAIT_2", args.hold); return

        fin = sess._recv(timeout=args.recv_timeout)
        if fin is not None and sess._flags(fin) & FIN:
            sess.ack = fin[TCP].seq + 1
            sess.send_ack()
        reached.release(); log(cid, f"TIME_WAIT (sport={sport})")
        park(sess, "TIME_WAIT", args.hold if args.hold else 240)

    except (TimeoutError, ConnectionRefusedError, RuntimeError, OSError) as e:
        log(cid, f"Fehler: {e}")


def setup_firewall(lo, hi):
    rng = str(lo) if lo == hi else f"{lo}:{hi}"
    rule = ["-p", "tcp", "--sport", rng, "--tcp-flags", "RST", "RST", "-j", "DROP"]
    try:
        subprocess.run(["iptables", "-A", "OUTPUT", *rule], check=True)
        print(f"[*] iptables: ausgehendes RST auf sport {rng} wird gedroppt")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"[!] iptables-Regel fehlgeschlagen ({e}). Manuell:\n"
              f"    sudo iptables -A OUTPUT -p tcp --sport {rng} "
              f"--tcp-flags RST RST -j DROP")
        return
    atexit.register(lambda: subprocess.run(
        ["iptables", "-D", "OUTPUT", *rule], stderr=subprocess.DEVNULL))


def main():
    p = argparse.ArgumentParser(
        description="Hält eine oder mehrere TCP/HTTP-Verbindungen in einem "
                    "wählbaren TCP-Zustand.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Zustände:\n  " + "\n  ".join(
            f"{s:<12} {'(Server muss schließen)' if s in PASSIVE_STATES else ''}"
            for s in STATES))
    p.add_argument("host", help="Zielhost (Name oder IP)")
    p.add_argument("-p", "--port", type=int, default=80, help="Zielport (Default 80)")
    p.add_argument("-s", "--state", required=True, choices=STATES,
                   help="Zielzustand, in dem geparkt wird")
    p.add_argument("-n", "--count", type=int, default=1,
                   help="Anzahl paralleler Verbindungen (Default 1)")
    p.add_argument("-t", "--hold", type=int, default=300,
                   help="Haltezeit in Sekunden, 0 = unendlich (Default 300)")
    p.add_argument("--http", action="store_true",
                   help="in ESTABLISHED zusätzlich einen HTTP-Request senden")
    p.add_argument("--method", default="GET", help="HTTP-Methode (Default GET)")
    p.add_argument("--path", default="/", help="HTTP-Pfad (Default /)")
    p.add_argument("--sport-base", type=int,
                   help="Basis-Quellport (sonst zufällig); genutzt werden "
                        "base .. base+count-1")
    p.add_argument("--ramp", type=float, default=0.0,
                   help="Verzögerung in s zwischen dem Start der Verbindungen")
    p.add_argument("--recv-timeout", type=float, default=5.0,
                   help="Timeout beim Warten auf Server-Pakete (s)")
    p.add_argument("--setup-firewall", action="store_true",
                   help="iptables-Regel gegen Kernel-RST für den Portbereich setzen")
    args = p.parse_args()

    if args.count < 1:
        sys.exit("--count muss >= 1 sein")
    if os.geteuid() != 0:
        print("[!] Warnung: ohne root schlagen raw sockets vermutlich fehl.",
              file=sys.stderr)

    base = args.sport_base or random.randint(20000, 60000 - args.count)
    ports = list(range(base, base + args.count))

    if args.setup_firewall:
        setup_firewall(ports[0], ports[-1])

    print(f"[*] Ziel: {args.state}  {args.host}:{args.port}  "
          f"{args.count} Verbindung(en)  sport {ports[0]}..{ports[-1]}")

    reached = threading.Semaphore(0)
    threads = []
    for i, sport in enumerate(ports):
        t = threading.Thread(target=run_session,
                             args=(i, args, sport, reached), daemon=True)
        t.start()
        threads.append(t)
        if args.ramp:
            time.sleep(args.ramp)

    # auf Erreichen des Zielzustands aller Verbindungen warten (best effort)
    got = 0
    for _ in range(args.count):
        if reached.acquire(timeout=max(10, args.recv_timeout * 2 + 5)):
            got += 1
    print(f"[*] {got}/{args.count} im Zustand {args.state}. "
          f"Halte {'unendlich' if args.hold == 0 else str(args.hold)+'s'}. "
          f"Strg-C zum Beenden.")

    try:
        for t in threads:
            while t.is_alive():
                t.join(timeout=0.5)
    except KeyboardInterrupt:
        print("\n[*] beende — Verbindungen werden NICHT sauber geschlossen.")
        _stop.set()


if __name__ == "__main__":
    main()
