import argparse
import signal
import sys
import os
from pyshark import *
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes

#created by b1n4ri0

prs = argparse.ArgumentParser()
prs.add_argument("capfile", help="network capture file '.cap' or '.pcap'", default=None)
prs.add_argument("-o", "--output", help="file name to save exported cert in .pem (must end with .pem extension)", default="server-cert.pem")
args = prs.parse_args()

capf = args.capfile
ofile = args.output

certs = []
srvrk = "server-key.pem"

def get_TLScert_fromfile(capf):
    if not os.path.exists(capf):
        print("[!] Error:", capf, "does not exist.")
        sys.exit(1)
    try: 
        print("[+] Trying to export TLS certs from:", capf)
        cap = FileCapture(capf, display_filter='tls.handshake.certificate')
    except Exception as e:
        print("[!] Error trying to open ", capf, ":", e)
        sys.exit(1)
    for packet in cap:
        cert_data = bytes.fromhex(packet.eap.tls_handshake_certificate.replace(':', ''))
        cert = x509.load_der_x509_certificate(cert_data, default_backend())      
        certs.append(cert)
    if not certs:
        print("[!] No TLS certificates found in the capture file. Exiting program.")
        sys.exit(1)
    print("[+] TLS certs successfully exported from:", capf)
    return certs


def delete_duplicated(certs):
    nondupcerts = set(certs)
    return list(nondupcerts)

def select_cert(nondupcerts):
    print("[+] Current certs:")
    for i, cer in enumerate(nondupcerts):
        print(f"\t[{i}]--[{cer}]")
    while True:
        try:
            select = int(input("[+] Select the cert number to export:"))
            if 0 <= select <= len(nondupcerts):
                slcert = nondupcerts[select]
                print("[+] Selected cert:", slcert)
                return slcert
            else:
                print("[!] Please select a valid number")
        except KeyboardInterrupt:
            print("\n\n[Ctrl+C] Exiting the program ...")

def generate_fakeTLScert(slcert, ofile):
    newcert = slcert
    priv_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    build = (
        x509.CertificateBuilder()
        .subject_name(newcert.subject)
        .issuer_name(newcert.issuer)
        .public_key(priv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(newcert.not_valid_before_utc)
        .not_valid_after(newcert.not_valid_after_utc)
    )
    for ext in newcert.extensions:
        build = build.add_extension(ext.value, critical=ext.critical)
    autosigned_cert = build.sign(
        private_key=priv_key, algorithm=hashes.SHA256(), backend=default_backend()
    )
    with open(srvrk, "wb") as file:
        file.write(priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    with open(ofile, 'wb') as fl:
        fl.write(autosigned_cert.public_bytes(serialization.Encoding.PEM))
    print("[+]", ofile, "and", srvrk, "successfully created ;)")

def sig_handle(sig, frame):
    print("\n\n[Ctrl+C] Exiting the program ...")
    sys.exit(0)

def main():
    if not args.output.endswith(".pem"):
        print("[!] Output file must end with .pem extension.")
        sys.exit(1)
    try:
        cr = get_TLScert_fromfile(capf)
        dd = delete_duplicated(cr)
        cert = select_cert(dd)
        generate_fakeTLScert(cert, ofile)
    except KeyboardInterrupt:
        print("\n\n[Ctrl+C] Exiting the program ...")
        sys.exit(0)
    except Exception as e:
        print("[!]", e)
        sys.exit(1)


if __name__ == '__main__':
    signal.signal(signal.SIGINT, sig_handle)
    main()