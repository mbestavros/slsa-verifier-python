import argparse, base64, hashlib, json

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
        provenance = f.read()

    provenance = json.loads(provenance)
    payload_decoded = base64.b64decode(provenance["payload"]).decode()
    payload_json = json.loads(payload_decoded)

    binary_digest = hashlib.sha256(binary).hexdigest()
    if payload_json["subject"][0]["digest"]["sha256"] == binary_digest:
        print("SHAs match!")


if __name__ == "__main__":
   main()
