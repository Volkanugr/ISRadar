#!/usr/bin/env python3
"""Small loopback-only TCP, UDP echo and HTTP fixtures. No external traffic."""
import argparse
import http.server
import socketserver
import threading


class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        return


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        payload, sock = self.request
        if len(payload) <= 4096:
            sock.sendto(payload, self.client_address)


class HTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_HEAD = do_GET
    do_OPTIONS = do_GET

    def log_message(self, *_args):
        return


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--udp-echo", action="store_true", help="Use echo on 9000; do not run alongside delivery receiver")
    args = parser.parse_args()
    servers = [socketserver.ThreadingTCPServer(("127.0.0.1", 9001), TCP),
               http.server.ThreadingHTTPServer(("127.0.0.1", 9002), HTTP)]
    if args.udp_echo:
        servers.append(socketserver.ThreadingUDPServer(("127.0.0.1", 9000), UDP))
    for server in servers:
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print("Loopback fixtures: TCP 9001, HTTP 9002" + (", UDP echo 9000" if args.udp_echo else ""), flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        for server in servers:
            server.shutdown()
            server.server_close()

