#!/usr/bin/env python3
"""tcpstate_async — hält viele TCP/HTTP-Verbindungen (echte Kernel-Sockets) in
einem natürlichen TCP-Zustand offen. asyncio, leichtgewichtig, skaliert auf
tausende Verbindungen auf einem Kern.

Einsatzzweck: Resilienz- und Leak-Tests gegen den EIGENEN Server/Proxy (z. B.
nginx): Wie verhält sich der Server, wenn viele Clients idle offen bleiben oder
in CLOSE_WAIT hängen? Greifen client_header_timeout / keepalive_timeout /
worker_connections wie erwartet, und schlägt das Monitoring an? Nur gegen
Systeme einsetzen, für die du die Erlaubnis hast.

Weil hier der Kernel die Verbindungen führt, sind die Zustände — anders als bei
der raw/scapy-Variante — auch auf dem Client im Socket-Table sichtbar
(ss, /proc/net/tcp, Telegraf netstat-Input).

Erreichbare Zustände (über OS-Sockets):
    ESTABLISHED   Verbindung offen gehalten (idle, voller oder partieller Request)
    CLOSE_WAIT    Request mit Connection: close -> Server-FIN empfangen, aber
                  eigenes close() zurückgehalten (häufigste Leak-Ursache)
    FIN_WAIT      eigenes FIN (Halb-Close) gesendet, Verbindung gehalten
                  (kernel-getimed, nur kurz beobachtbar)

Kein root nötig (normale Sockets).
"""

import argparse
import asyncio
import socket
import sys
import time

STATES = ["ESTABLISHED", "CLOSE_WAIT", "FIN_WAIT"]


class Stats:
    def __init__(self):
        self.active = 0
        self.reached = 0
        self.failed = 0


def http_request(host, method, path, connection, partial=False):
    if partial:
        # Unvollständiger Header (kein abschließendes CRLFCRLF): die Verbindung
        # bleibt in der Request-Read-Phase. Testet nginx client_header_timeout.
        return (f"{method} {path} HTTP/1.1\r\n"
                f"Host: {host}\r\nUser-Agent: tcpstate\r\nX-Pad: ").encode()
    return (f"{method} {path} HTTP/1.1\r\n"
            f"Host: {host}\r\nUser-Agent: tcpstate\r\n"
            f"Connection: {connection}\r\n\r\n").encode()


def set_keepalive(sock, idle=30, interval=10, count=5):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    for opt, val in (("TCP_KEEPIDLE", idle), ("TCP_KEEPINTVL", interval),
                     ("TCP_KEEPCNT", count)):
        if hasattr(socket, opt):
            sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, opt), val)


async def wait_hold(hold, stop):
    if hold == 0:
        await stop.wait()
    else:
        try:
            await asyncio.wait_for(stop.wait(), timeout=hold)
        except asyncio.TimeoutError:
            pass


async def read_response(reader, timeout=5):
    """Antwort best effort lesen (für keepalive/FIN-Pfade); EOF signalisiert FIN."""
    try:
        return await asyncio.wait_for(reader.read(65536), timeout=timeout)
    except asyncio.TimeoutError:
        return b""


async def hold_conn(cid, args, stats, stop):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(args.host, args.port),
            timeout=args.connect_timeout)
    except (OSError, asyncio.TimeoutError) as e:
        stats.failed += 1
        return

    sock = writer.get_extra_info("socket")
    if sock and args.keepalive:
        set_keepalive(sock)

    stats.active += 1
    try:
        if args.state == "ESTABLISHED":
            if args.http:
                writer.write(http_request(args.host, args.method, args.path,
                                          "keep-alive"))
                await writer.drain()
                await read_response(reader, args.recv_timeout)
            elif args.partial:
                writer.write(http_request(args.host, args.method, args.path,
                                          "keep-alive", partial=True))
                await writer.drain()
            # sonst: reine idle-Verbindung, nichts senden
            stats.reached += 1
            await wait_hold(args.hold, stop)

        elif args.state == "CLOSE_WAIT":
            writer.write(http_request(args.host, args.method, args.path, "close"))
            await writer.drain()
            # bis EOF lesen -> Server hat geantwortet und FIN geschickt.
            # Danach KEIN writer.close(): unser Socket bleibt in CLOSE_WAIT.
            try:
                while True:
                    chunk = await asyncio.wait_for(reader.read(65536),
                                                   timeout=args.recv_timeout)
                    if not chunk:
                        break
            except asyncio.TimeoutError:
                pass
            stats.reached += 1
            await wait_hold(args.hold, stop)

        elif args.state == "FIN_WAIT":
            writer.write(http_request(args.host, args.method, args.path, "close"))
            await writer.drain()
            await read_response(reader, args.recv_timeout)
            # Halb-Close: eigenes FIN senden, Verbindung aber nicht freigeben.
            try:
                if sock:
                    sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            stats.reached += 1
            await wait_hold(args.hold, stop)

    finally:
        stats.active -= 1
        try:
            writer.close()
        except OSError:
            pass


async def stats_loop(args, stats, stop, n):
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=args.stats_interval)
        except asyncio.TimeoutError:
            pass
        print(f"[stats] aktiv={stats.active}/{n}  "
              f"erreicht={stats.reached}  fehlgeschlagen={stats.failed}")


async def amain(args):
    stop = asyncio.Event()
    stats = Stats()
    n = args.count

    print(f"[*] Ziel: {args.state}  {args.host}:{args.port}  {n} Verbindung(en)")

    tasks = []
    stats_task = asyncio.create_task(stats_loop(args, stats, stop, n))
    for i in range(n):
        tasks.append(asyncio.create_task(hold_conn(i, args, stats, stop)))
        if args.ramp:
            await asyncio.sleep(args.ramp)

    print(f"[*] gestartet. Halte "
          f"{'unendlich' if args.hold == 0 else str(args.hold)+'s'}. "
          f"Strg-C zum Beenden.")
    try:
        await asyncio.gather(*tasks)
    finally:
        stop.set()
        stats_task.cancel()


def main():
    p = argparse.ArgumentParser(
        description="Hält viele TCP/HTTP-Verbindungen (OS-Sockets) in einem "
                    "natürlichen TCP-Zustand offen.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Zustände: " + ", ".join(STATES))
    p.add_argument("host", help="Zielhost (Name oder IP)")
    p.add_argument("-p", "--port", type=int, default=80, help="Zielport (Default 80)")
    p.add_argument("-s", "--state", required=True, choices=STATES,
                   help="Zielzustand, in dem gehalten wird")
    p.add_argument("-n", "--count", type=int, default=1,
                   help="Anzahl paralleler Verbindungen (Default 1)")
    p.add_argument("-t", "--hold", type=int, default=300,
                   help="Haltezeit in Sekunden, 0 = unendlich (Default 300)")
    p.add_argument("--http", action="store_true",
                   help="ESTABLISHED: vollständigen keep-alive-Request senden")
    p.add_argument("--partial", action="store_true",
                   help="ESTABLISHED: unvollständigen Header senden "
                        "(testet client_header_timeout)")
    p.add_argument("--method", default="GET", help="HTTP-Methode (Default GET)")
    p.add_argument("--path", default="/", help="HTTP-Pfad (Default /)")
    p.add_argument("--keepalive", action="store_true",
                   help="SO_KEEPALIVE auf den Client-Sockets aktivieren")
    p.add_argument("--ramp", type=float, default=0.0,
                   help="Verzögerung in s zwischen Verbindungsstarts")
    p.add_argument("--connect-timeout", type=float, default=5.0)
    p.add_argument("--recv-timeout", type=float, default=5.0)
    p.add_argument("--stats-interval", type=float, default=5.0,
                   help="Statusausgabe-Intervall in s")
    args = p.parse_args()

    if args.count < 1:
        sys.exit("--count muss >= 1 sein")

    try:
        asyncio.run(amain(args))
    except KeyboardInterrupt:
        print("\n[*] abgebrochen — Sockets werden geschlossen.")


if __name__ == "__main__":
    main()
