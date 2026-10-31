#!/usr/bin/env python3
"""Generate public, test-only CA/leaf/key DER fixtures using local OpenSSL."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
out = ROOT / "external-agent/tests/fixtures/tls"
out.mkdir(parents=True, exist_ok=True)

with tempfile.TemporaryDirectory(prefix="isradar-cert-") as directory:
    work = Path(directory)
    def openssl(*args):
        subprocess.run(["openssl", *args], cwd=work, check=True, capture_output=True)
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", "ca.key", "-out", "ca.pem", "-days", "3650", "-subj", "/CN=ISRadar TEST ONLY CA",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", "server.key", "-out", "server.csr", "-subj", "/CN=validator.example")
    (work / "extensions").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:validator.example\n")
    openssl("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
            "-CAcreateserial", "-out", "server.pem", "-days", "3650", "-extfile", "extensions")
    (work / "index").touch()
    (work / "serial").write_text("1000\n")
    (work / "ca.conf").write_text("[ca]\ndefault_ca=local\n[local]\ndatabase=index\nserial=serial\nnew_certs_dir=.\ncertificate=ca.pem\nprivate_key=ca.key\ndefault_md=sha256\npolicy=policy\n[policy]\ncommonName=supplied\n")
    openssl("ca", "-batch", "-config", "ca.conf", "-in", "server.csr", "-out", "expired.pem",
            "-startdate", "20200101000000Z", "-enddate", "20210101000000Z", "-extfile", "extensions")
    for name in ("ca", "server", "expired"):
        openssl("x509", "-in", name + ".pem", "-outform", "DER", "-out", str(out / (name + ".der")))
    openssl("pkcs8", "-topk8", "-nocrypt", "-in", "server.key", "-outform", "DER", "-out", str(out / "server-key.der"))
print("Generated test-only fixtures. server-key.der is public test key material; never deploy it.")
