import os
import json
import sys
import hmac
import argparse
import base58
import hashlib
from bech32 import bech32_encode, convertbits
from ecdsa import SECP256k1, SigningKey
from ecdsa.util import string_to_number, number_to_string


def hash160(data: bytes) -> bytes:
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()
def p2pkh_address(pubkey: bytes) -> str:
    h160 = hash160(pubkey)
    versioned = b'\x00' + h160
    checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
    return base58.b58encode(versioned + checksum).decode()
def p2sh_address(script_hash: bytes) -> str:
    versioned = b'\x05' + script_hash
    checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
    return base58.b58encode(versioned + checksum).decode()
def p2wpkh_address(pubkey: bytes) -> str:
    h160 = hash160(pubkey)
    converted = convertbits(h160, 8, 5)
    return bech32_encode("bc", [0] + converted)

def parse_index(component: str):
    # change path 
    if component == 'm' or component == '' or component is None:
        return None
    hardened = component.endswith("'")
    num = component[:-1] if hardened else component
    idx = int(num)
    if hardened:
        idx |= 0x80000000
    return idx
def check_private_key(IL):
    ILINT = int.from_bytes(IL,"big")
    # invalid if zero or >= curve order
    if ILINT == 0 or ILINT >= curve_order:
        raise ValueError("Invalid private key")
def seed_to_master_key(seed: bytes):
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    IL = I[:32]
    IR = I[32:]
    # check if error
    check_private_key(IL)
    return I[:32], I[32:]  # (privkey, chaincode)
def derive_child_private_key(parent_privkey: bytes, parent_chaincode: bytes, index: int):
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
def private_key_to_public_key(privkey: bytes):
    sk = SigningKey.from_string(privkey, curve=SECP256k1)
    vk = sk.get_verifying_key()
    pubkey = b'\x02' + number_to_string(vk.pubkey.point.x(), curve_order)
    if vk.pubkey.point.y() % 2 != 0:
        pubkey = b'\x03' + number_to_string(vk.pubkey.point.x(), curve_order)
    # return the compressed public key bytes
    return pubkey
def go_throw_path(seed: bytes, path: str):
    IL, IR = seed_to_master_key(seed_bytes)
    pathArr = path.split("/")
    for comp in pathArr:
        idx = parse_index(comp)
        if idx is None:
            continue
        IL, IR = derive_child_private_key(IL, IR, idx)
    return IL
def make_wallet_data(name, path, addr_type, privacy, private_key):
    filename = f"./{name}.json"
    if not os.path.exists(filename):
        # create an empty wallet file
        data = {}
        with open(filename, "w") as f:
            json.dump(data, f)
    else:
        with open(filename, "r") as file:
            data = json.load(file)
    
    if not isinstance(data, dict):
        raise ValueError(f"wallet file {filename} does not contain an object")

    entry = {
        "type": addr_type,
        "privacy": privacy,
        "path": path,
        "address": public_key_to_address(private_key_to_public_key(private_key), addr_type),
        "public-key": private_key_to_public_key(private_key).hex(),
        "private-key-enc": pivate_key_enc(private_key).hex(),
        "balance": 0,
        "transactions": []
    }
   
    if path in data:
        print(f"entry for path {path} already exists in {filename}, aborting")
        
        sys.exit(1)

    data[path] = entry
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)

    print(f"added entry for {path} to {filename}")
    return entry
def pivate_key_enc(pivate_key):
    # simple hex encoding for now
    return pivate_key
def public_key_to_address(pubkey: bytes, addr_type: str):
    match addr_type:
        case 'p2pkh':
            return p2pkh_address(pubkey)
        case 'p2wpkh' | 'bip-84':
            return p2wpkh_address(pubkey)
        case _:
            raise ValueError(f"Unsupported address type: {addr_type}")
        
        
    
parser = argparse.ArgumentParser()
parser.add_argument("name", help="Wallet name")
parser.add_argument("path", help="Wallet path")
parser.add_argument("type", help="Address type")
parser.add_argument("-p", "--privacy", type=int, help="Privacy off address: 0 heavy verification, 1 light verification, 2 none")
parser.add_argument("-s", "--seed", type=lambda s: bytes.fromhex(s), help="Seed value as hex string (without 0x)")
parser.add_argument("password", help="Private key encryption password")
args = parser.parse_args()

print()
print("ID:", args.path)
print("Name:", args.name)
print("Type:", args.type)
print("Privacy:", args.privacy)
print("Seed:", args.seed)
print()

curve = SECP256k1
curve_order = curve.order

seed_bytes = args.seed

priv = go_throw_path(seed_bytes, args.path)

make_wallet_data(args.name, args.path, args.type, args.privacy, priv)
