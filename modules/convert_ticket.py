import base64
import os
import struct
import pyperclip
from core.colors import red, green, yellow, blue
from core.helpers import save_loot
from impacket.krb5.ccache import CCache
from impacket.krb5 import constants

def is_ccache(data: bytes) -> bool:
    return len(data) > 0 and struct.unpack(">B", data[0:1])[0] == 0x5

def is_kirbi(data: bytes) -> bool:
    return len(data) > 0 and struct.unpack(">B", data[0:1])[0] == 0x76

def convert_ticket():
    print(blue("[*] Ticket Converter"))

    file_path = input("[?] Enter path to ticket file (or leave blank for stdin input): ").strip()

    if not file_path:
        print(yellow("[*] Waiting for base64 ticket input..."))
        raw = input().strip().encode()
        if not raw:
            print(red("[-] No data provided. Aborting."))
            return
    else:
        if not os.path.exists(file_path):
            print(red(f"[-] File not found: {file_path}"))
            return
        with open(file_path, 'rb') as f:
            raw = f.read().strip()
        if not raw:
            print(red("[-] File is empty. Aborting."))
            return

    filetype = None
    if raw.startswith(b"doI"):
        filetype = "b64kirbi"
    elif is_ccache(raw):
        filetype = "ccache"
    elif is_kirbi(raw):
        filetype = "kirbi"

    if filetype == "ccache":
        print(blue("[*] Detected .ccache ticket"))
        ccache = CCache.loadFile(file_path)
        kirbi = ccache.toKRBCRED()
        encoded = base64.b64encode(kirbi).decode()
        print(green("[+] Converted to base64 .kirbi:\n"))
        print(encoded)

    elif filetype in ("kirbi", "b64kirbi"):
        print(blue(f"[*] Detected {'Base64 ' if filetype == 'b64kirbi' else ''}.kirbi ticket"))
        ccache = CCache()
        try:
            if filetype == "kirbi":
                ccache.fromKRBCRED(raw)
            else:
                kirbi = base64.b64decode(raw)
                ccache.fromKRBCRED(kirbi)
        except Exception as e:
            print(red(f"[-] Failed to convert: {e}"))
            return

        cred = ccache.credentials[0]
        principal = cred['client'].prettyPrint().split(b'@')[0].decode()
        spn = cred['server'].prettyPrint().split(b'@')[0].decode()
        flags = []

        for k in constants.TicketFlags:
            if ((cred['tktflags'] >> (31 - k.value)) & 1) == 1:
                flags.append(constants.TicketFlags(k.value).name)

        print(green(f"[+] Ticket Info: {principal} -> {spn} [ {', '.join(flags)} ]"))

        outfile = f"{principal}@{spn.replace('/', '_')}.ccache"
        ccache_data = ccache.getData()
        save_loot(outfile, ccache_data, binary=True)

        export_line = f"export KRB5CCNAME='loot/{outfile}'"
        pyperclip.copy(export_line)

        print(green(f"[+] Saved ccache to loot/{outfile}"))
        print(yellow(f"[i] Use with: {export_line} && nxc smb ... --use-kcache"))
        print(green("[+] Copied export command to clipboard!"))

    else:
        print(red("[-] Unknown or unsupported ticket format."))
