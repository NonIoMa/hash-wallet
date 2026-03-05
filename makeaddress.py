import os
import json
import hashlib
from ecdsa import SECP256k1, SigningKey
from ecdsa.util import string_to_number, number_to_string
import hmac
import base58
from bech32 import bech32_encode, convertbits
import argparse

def public_key_to_address(pubkey: bytes, addr_type: str):
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
def hash160(data: bytes) -> bytes:
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()       
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
def derive_child_private_key(parent_privkey: bytes, parent_chaincode: bytes, index: int):
    """Derive a single child private key from parent using index."""
    if index >= 0x80000000:
        data = b'\x00' + parent_privkey + index.to_bytes(4, 'big')
    else:
        sk = SigningKey.from_string(parent_privkey, curve=SECP256k1)
        vk = sk.get_verifying_key()
        x = number_to_string(vk.pubkey.point.x(), curve_order)
        prefix = b'\x02' if vk.pubkey.point.y() % 2 == 0 else b'\x03'
        data = prefix + x + index.to_bytes(4, 'big')

    I = hmac.new(parent_chaincode, data, hashlib.sha512).digest()
    IL = I[:32]
    IR = I[32:]

    IL_int = int.from_bytes(IL, 'big')
    parent_int = int.from_bytes(parent_privkey, 'big')

    if IL_int >= curve_order:
        raise ValueError("Invalid IL")

    child_int = (IL_int + parent_int) % curve_order

    if child_int == 0:
        raise ValueError("Invalid child key")

    child_privkey = child_int.to_bytes(32, 'big')

    return child_privkey, IR
def private_key_to_public_key(privkey: bytes) -> bytes:
    """Return compressed public key from private key."""
    sk = SigningKey.from_string(privkey, curve=SECP256k1)
    vk = sk.get_verifying_key()
    pub = b'\x02' + number_to_string(vk.pubkey.point.x(), curve_order)
    if vk.pubkey.point.y() % 2 != 0:
        pub = b'\x03' + number_to_string(vk.pubkey.point.x(), curve_order)
    return pub
def pivate_key_enc(private_key: bytes) -> bytes:
    # placeholder for private key encryption, currently identity function
    return private_key
def derive_path(master_priv: bytes, master_chaincode: bytes, path: str) -> bytes:
    """Derive a child private key from master key and chaincode using the BIP32 path."""
    priv = master_priv
    chaincode = master_chaincode
    for comp in path.split("/"):
        idx = parse_index(comp)
        if idx is None:
            continue
        priv, chaincode = derive_child_private_key(priv, chaincode, idx)
    return priv

parser = argparse.ArgumentParser()
parser.add_argument("name", help="Wallet name")
parser.add_argument("path", help="Wallet derivation path")
parser.add_argument("type", help="Address type")
parser.add_argument("-p", "--privacy", type=int, help="Privacy level: 0 heavy, 1 light, 2 none")
parser.add_argument("password1", help="Private key encryption password")
args = parser.parse_args()

print()
print("Name:", args.name)
print("ID:", args.path)
print("Type:", args.type)
print("Privacy:", args.privacy)
print("I wont print password, what did you expect ?")
print()

curve = SECP256k1
curve_order = curve.order

# load wallet master key
wallet_file = os.path.join(".", f"{args.name}.json")
with open(wallet_file, "r") as f:
    wallet_data = json.load(f)
master_entry = wallet_data.get("m")
if master_entry is None:
    raise ValueError("wallet file does not contain master key")
master_priv_enc = bytes.fromhex(master_entry["private-key-enc"])
master_chaincode = bytes.fromhex(master_entry["chaincode"])
# decrypt if necessary (currently identity)
master_priv = master_priv_enc

# derive child private key for this path
child_priv = derive_path(master_priv, master_chaincode, args.path)

# compute address and build entry
pubkey = private_key_to_public_key(child_priv)
entry = {
    "path": args.path,
    "public-key": pubkey.hex(),
    "type": args.type,
    "address": public_key_to_address(pubkey, args.type),
    "private-key-enc": pivate_key_enc(child_priv).hex(),
    "privacy": args.privacy,
    "balance": 0,
    "transactions": []
}

# append entry to wallet data
wallet_data.setdefault("addresses", []).append(entry)
with open(wallet_file, "w") as f:
    json.dump(wallet_data, f, indent=2)

print(f"Added address entry to {wallet_file}")
