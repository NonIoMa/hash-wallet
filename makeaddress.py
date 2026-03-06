"""Address derivation utility for hash-wallet.

This tool reads the master key from an existing wallet JSON file, decrypts
it with a password, derives a child private key using the supplied BIP32
path, and appends an address entry to the wallet.  Each derived key is
encrypted with a second password.
"""

import argparse
import os
import json
import hmac
import hashlib
import base58
from bech32 import bech32_encode, convertbits
from ecdsa import SECP256k1, SigningKey
from ecdsa.util import number_to_string
from crypto_utils import encrypt_private_key, decrypt_private_key
from bip32_utils import derive_child_private_key, derive_path, parse_index, private_key_to_public_key

def hash160(data: bytes) -> bytes:
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()
    """Return a human-readable address for ``pubkey`` of ``addr_type``.

    Supported types:
    * ``p2pkh`` – legacy Base58Pay‑to‑Public‑Key‑Hash
    * ``p2wpkh`` / ``bip-84`` – native SegWit Bech32
    """
    match addr_type:
        case 'p2pkh':
            h160 = hash160(pubkey)
            versioned = b'\x00' + h160
            checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
            return base58.b58encode(versioned + checksum).decode()
        case 'p2wpkh' | 'bip-84':
            h160 = hash160(pubkey)
            converted = convertbits(h160, 8, 5)
            return bech32_encode("bc", [0] + converted)
        case _:
            raise ValueError(f"Unsupported address type: {addr_type}")
def parse_index(component: str):
    # convert a path component (e.g. 44' or 0) into integer index
    if component == 'm' or component == '' or component is None:
        return None
    hardened = component.endswith("'")
    num = component[:-1] if hardened else component
    idx = int(num)
    if hardened:
        idx |= 0x80000000
    return idx
def derive_child_private_key(parent_privkey: bytes, parent_chaincode: bytes, index: int) -> tuple[bytes, bytes]:
    """Derive a single BIP32 child private key.

    ``index`` may be hardened (>= 0x80000000) or normal.  Returns a tuple
    ``(child_privkey, child_chaincode)``.
    """
    if index >= 0x80000000:
        data = b'\x00' + parent_privkey + index.to_bytes(4, 'big')
    else:
        sk = SigningKey.from_string(parent_privkey, curve=SECP256k1)
        vk = sk.get_verifying_key()
        x = number_to_string(vk.pubkey.point.x(), SECP256k1.order)
        prefix = b'\x02' if vk.pubkey.point.y() % 2 == 0 else b'\x03'
        data = prefix + x + index.to_bytes(4, 'big')

    I = hmac.new(parent_chaincode, data, hashlib.sha512).digest()
    IL = I[:32]
    IR = I[32:]

    IL_int = int.from_bytes(IL, 'big')
    parent_int = int.from_bytes(parent_privkey, 'big')

    order = SECP256k1.order
    if IL_int >= order:
        raise ValueError("Invalid IL")

    child_int = (IL_int + parent_int) % order

    if child_int == 0:
        raise ValueError("Invalid child key")

    child_privkey = child_int.to_bytes(32, 'big')

    return child_privkey, IR
# the wallet-wide encryption scheme is handled by crypto_utils. This stub
# remains only to satisfy older scripts that might import it.
def private_key_enc(private_key: bytes) -> bytes:
    """Identity fallback for backwards compatibility."""
    return private_key
def derive_path(master_priv: bytes, master_chaincode: bytes, path: str) -> tuple[bytes, bytes]:
    """Derive a child private key and chaincode from master key using the BIP32 path.
    
    Returns a tuple (child_privkey, child_chaincode).
    """
    priv = master_priv
    chaincode = master_chaincode
    for comp in path.split("/"):
        idx = parse_index(comp)
        if idx is None:
            continue
        priv, chaincode = derive_child_private_key(priv, chaincode, idx)
    return priv, chaincode



def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Derive a child address and add it to a wallet")
    parser.add_argument("name", help="Wallet name")
    parser.add_argument("path", help="BIP32 derivation path, e.g. m/84'/0'/0'/0/0")
    parser.add_argument("type", help="Address type (p2pkh, p2wpkh, bip-84)")
    parser.add_argument("password_root", help="Password used to decrypt the master private key")
    parser.add_argument("password_parent", help="Password used to decrypt the parent key")
    parser.add_argument("password_address", help="Password used to encrypt the derived address key")
    args = parser.parse_args()

    return args


def main() -> None:
    args = _parse_args()

    print()
    print("Name:", args.name)
    print("ID:", args.path)
    print("Type:", args.type)
    print("I wont print passwords, what did you expect ?")
    print()



    # load wallet
    wallet_file = os.path.join(".", f"{args.name}.json")
    with open(wallet_file, "r") as f:
        wallet_data = json.load(f)
    wallet = wallet_data.get("wallet", {})
    master_entry = wallet.get("master")
    if master_entry is None:
        raise ValueError("wallet file does not contain wallet.master")
    master_priv_enc = bytes.fromhex(master_entry["private-key-enc"])
    master_chaincode = bytes.fromhex(master_entry["chaincode"])
    # decrypt master private key using the root password
    try:
        master_priv = decrypt_private_key(master_priv_enc, args.password_root)
    except Exception as exc:  # cryptography throws InvalidTag on auth failure
        raise ValueError("unable to decrypt master private key - bad root password?") from exc

    # derive child private key for this path
    # find parent entry - look for the longest matching parent path
    parent_entry = None
    parent_path = None
    for key in wallet.keys():
        if key == "master":
            continue
        candidate = wallet.get(key)
        # Check if this key is a parent (has chaincode) and matches our path
        if isinstance(candidate, dict) and "chaincode" in candidate:
            if args.path.startswith(key + "/"):
                if parent_path is None or len(key) > len(parent_path):
                    parent_entry = candidate
                    parent_path = key
    
    if parent_entry is not None:
        # load and decrypt existing parent key
        parent_priv_enc = bytes.fromhex(parent_entry["private-key-enc"])
        parent_chaincode = bytes.fromhex(parent_entry["chaincode"])
        try:
            parent_priv = decrypt_private_key(parent_priv_enc, args.password_parent)
        except Exception as exc:
            raise ValueError("unable to decrypt parent private key - bad parent password?") from exc

        # figure out path relative to the stored parent
        rel_path = args.path
        if parent_path and rel_path.startswith(parent_path + "/"):
            rel_path = rel_path[len(parent_path) + 1 :]
        elif rel_path == parent_path:
            rel_path = ""

        child_priv, _ = derive_path(parent_priv, parent_chaincode, rel_path)
    else:
        # no parent entry in wallet; user must create one first
        comps = args.path.split("/")
        if len(comps) > 1:
            parent_path = "/".join(comps[:-1])
        else:
            parent_path = args.path
        
        print(f"\nERROR: No parent entry found in wallet.")
        print(f"Please create a parent key first using makeparent.py:")
        print(f"  python makeparent.py {args.name} {parent_path} password_root password_parent")
        print()
        raise ValueError("Parent entry required. Please run makeparent.py first.")

    # compute address and build entry
    pubkey = private_key_to_public_key(child_priv)
    
    entry = {
        "public-key": pubkey.hex(),
        "type": args.type,
        "address": public_key_to_address(pubkey, args.type),
        # encrypt child private key with the address password before storing
        "private-key-enc": encrypt_private_key(child_priv, args.password_address).hex(),
        "balance": 0,
        "transactions": []
    }

    # append entry to wallet data using path as key
    wallet[args.path] = entry
    wallet_data["wallet"] = wallet
    with open(wallet_file, "w") as f:
        json.dump(wallet_data, f, indent=2)

    print(f"Added address at {args.path} to {wallet_file}")


if __name__ == "__main__":
    main()
