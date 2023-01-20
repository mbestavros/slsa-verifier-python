import argparse, base64, hashlib, json

import sigstore_helpers, signing_spec, ecdsa

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

#from sigstore import

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--binary", help="Local path of binary to verify", default="artifacts/binary-linux-amd64", action="store")
    parser.add_argument("-p", "--provenance", help="Local path of binary provenance", default="artifacts/binary-linux-amd64.intoto.jsonl", action="store")
    args = parser.parse_args()

    binary = args.binary
    provenance = args.provenance

    with open("artifacts/binary-linux-amd64", "rb") as f:
        binary = f.read()

    with open("artifacts/binary-linux-amd64.intoto.jsonl", "r") as f:
        provenance_bytes = f.read()

    provenance = json.loads(provenance_bytes)
    payload_decoded = base64.b64decode(provenance["payload"]).decode()
    payload_json = json.loads(payload_decoded)

    binary_digest = hashlib.sha256(binary).hexdigest()
    if payload_json["subject"][0]["digest"]["sha256"] == binary_digest:
        print(f"{binary_digest}: SHAs match!")

    entries_result = sigstore_helpers.search(hash=binary_digest)
    entries = entries_result.json()

    rekor = sigstore_helpers.get_rekor_client()

    rekor_entry_api = rekor.log.entries

    for e in entries:
        # TODO: Actually verify the entry inclusion
        retrieved_entry = rekor_entry_api.get(uuid=e)
        body = json.loads(base64.b64decode(retrieved_entry.body).decode())

        # TODO: Actually verify the certificate against Fulcio
        certificate_bin = base64.b64decode(body["spec"]["publicKey"])

        cert = x509.load_pem_x509_certificate(certificate_bin)

        pubkey = cert.public_key()

        verifier = ecdsa.Verifier(pubkey)

        result = signing_spec.Verify(provenance_bytes, [('mykey', verifier)])

        print(result)

        # TODO: Actually check if integrated_time is within expiry
        integrated_time = retrieved_entry.integrated_time



if __name__ == "__main__":
   main()
