#!/usr/bin/env python3

import os
import sys
import subprocess
import argparse
import datetime
import json
import tempfile
import zipfile
import hashlib
import pprint

# openssl dgst -sha256 -sign snakeoil.key -out some-file.sha256 some-file 
# openssl dgst -sha256  -verify  snakeoil.pub -signature some-file.sha256 some-file

def die(*args, **kwargs):
    print(*args, **kwargs)
    sys.exit(1)

def verify_claim(encoded_json, signature, pubkey_path):
    with tempfile.TemporaryDirectory() as temp_path:
        sigpath = os.path.join(temp_path, 'proof.sig')
        jsonpath = os.path.join(temp_path, 'claim.json')

        with open(sigpath, mode='wb') as sigfile:
            sigfile.write(signature)

        with open(jsonpath, mode='wb') as jsonfile:
            jsonfile.write(encoded_json)

        print('sigfile', sigpath)
        print('jsonfile', jsonpath)

        #import pdb; pdb.set_trace()

        try:
            openssl_result = subprocess.check_output(
                    ['openssl', 'dgst', '-sha256', '-verify', pubkey_path, '-signature', sigpath, jsonpath])
        except subprocess.CalledProcessError as e:
            # TODO handle verification error here
            print(e)
            return False
    return True


def hash_file(path):
    hasher = hashlib.sha256()
    with open(args.file, 'rb') as f:
        hasher.update(f.read())
    sha256_hex = hasher.hexdigest()

def hash_bytes(b):
    return hashlib.sha256(b).hexdigest()

def do_mint(args):
    filesize = os.path.getsize(args.file)

    sha256_hex = hash_file(args.file)

    filename= os.path.basename(args.file)
    name, _ = os.path.splitext(args.file)
    receipt_path = name + ".receipt"

    print(filename, name, receipt_path)

    if os.path.isfile(receipt_path) and (not args.overwrite):
        print(f"Receipt file {receipt_path} already exists!")
        sys.exit(1)

    works = []
    works.append({
        'size': str(filesize),
        'title': filename, # TODO use real title
        'sha256': sha256_hex
        })

    date = datetime.datetime.utcnow().isoformat()[:-3] + 'Z'
    claim = {
            'works': works,
            'date': date,
            'message': args.message
            }

    claim_json = json.dumps(claim)
    encoded_json = claim_json.encode('utf-8')
    print(f"Signing JSON:\n'{claim_json}'")

    signature = None

    with tempfile.NamedTemporaryFile(mode='wb') as f:
        print(f"Writing JSON to temporary file {f.name}")
        f.write(encoded_json)

        try:
            signature = subprocess.check_output(['openssl', 'dgst', '-sha256', '-sign', args.prikey, f.name])
        except subprocess.CalledProcessError as e:
            print(e)
            return

    if signature is None:
        print("Signing failed.")
        sys.exit(1)

    roundtrip_success = verify_claim(encoded_json, signature, args.pubkey)
    if not roundtrip_success:
        die("Rountrip test failed")

    print(f"Signature: {signature}")

    print(f"json hash: {hash_bytes(encoded_json)}")
    print(f"signature hash: {hash_bytes(signature)}")

    with zipfile.ZipFile(receipt_path, mode='w', compression=zipfile.ZIP_STORED, allowZip64=False) as z:
        z.writestr('claim.json', encoded_json)
        z.writestr('signature.sha256', signature)

    print(f"Wrote receipt to '{receipt_path}'")


def do_verify(args):
    print("verify", args)
    sha256_hex = hash_file(args.file)

    with zipfile.ZipFile(args.receipt, 'r') as f:
        encoded_json = f.read('claim.json')
        signature = f.read('signature.sha256')

    print(f"json hash: {hash_bytes(encoded_json)}")
    print(f"signature hash: {hash_bytes(signature)}")

    # openssl dgst -sha256  -verify  snakeoil.pub -signature some-file.sha256 some-file

    success = verify_claim(encoded_json, signature, args.pubkey)

    if not success:
        die("Verification failed")

    claim_json = encoded_json.decode('utf-8')

    print(f"Signature: {signature.hex()}")
    #print(f"openssl_result: {openssl_result}")
    print(f"Claim JSON: '{claim_json}'")
    claim = json.loads(claim_json)
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(claim)
    ##print(f"Claim object: '{claim}'")

def do_genkeys(args):
    print("genkeys", args)

parser = argparse.ArgumentParser(prog='artsign')
subparsers = parser.add_subparsers(description='Valid subcommands', dest='subparser_name')

mint = subparsers.add_parser('mint', help='Mint a new receipt')
verify = subparsers.add_parser('verify', help='Verify a file with its receipt')
genkeys = subparsers.add_parser('genkeys', help='Generate a new keypair')

mint.set_defaults(func=do_mint)
mint.add_argument('file', type=str, help='The artwork in question')
mint.add_argument('--prikey', default='key.pem', type=str, help='Private key location')
mint.add_argument('--pubkey', default='public.pem', type=str, help='Public key location for roundtrip testing')
mint.add_argument('--message', default='', type=str, help='A custom message stored in the receipt')
mint.add_argument('--overwrite', default=False, action='store_true', help='Overwrite an existing receipt if it exists.')

verify.set_defaults(func=do_verify)
verify.add_argument('file', type=str, help='The artwork in question')
verify.add_argument('receipt', type=str, help='Receipt location')
verify.add_argument('--pubkey', default='key.pub', type=str, help='Public key location')

genkeys.set_defaults(func=do_genkeys)
genkeys.add_argument('--pubkey', default='key.pub', type=str, help='New public key name')
genkeys.add_argument('--prikey', default='key.pem', type=str, help='New private key name')

args = parser.parse_args()
args.func(args) # A nice trick: calls the "set_defaults" function of the given subcommand.
