import os
import json
import hmac
import argparse
import hashlib
from mnemonic import Mnemonic
from ecdsa import SECP256k1, SigningKey
from ecdsa.util import  number_to_string

BITCOIN_SEED = b"Bitcoin seed"

def mnemonic_to_seed(mnemonic_phrase: str, passphrase: str = "") -> bytes:
    """Convert BIP39 mnemonic phrase to seed using PBKDF2."""
    mnemonic_generator = Mnemonic("english")
    if not mnemonic_generator.check(mnemonic_phrase):
        raise ValueError("Invalid mnemonic phrase")
    return mnemonic_generator.to_seed(mnemonic_phrase, passphrase)
def hash160(data: bytes) -> bytes:
    """Compute RIPEMD160(SHA256(data))."""
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()       
def seed_to_master_key(seed: bytes):
    """Derive master key and chain code from BIP32 seed."""
    I = hmac.new(BITCOIN_SEED, seed, hashlib.sha512).digest()
    return I[:32], I[32:]  # (privkey, chaincode)
def private_key_to_public_key(privkey: bytes, curve_order: int) -> bytes:
    """Convert private key to compressed public key."""
    sk = SigningKey.from_string(privkey, curve=SECP256k1)
    vk = sk.get_verifying_key()
    pubkey = b'\x02' + number_to_string(vk.pubkey.point.x(), curve_order)
    if vk.pubkey.point.y() % 2 != 0:
        pubkey = b'\x03' + number_to_string(vk.pubkey.point.x(), curve_order)
    return pubkey
def write_wallet_data(name, private_key_enc, chaincode, public_key, reset):
    """Write wallet data to JSON file."""
    filename = os.path.join(".", f"{name}.json")
    if not os.path.exists(filename):
        # create an empty wallet file
        data = {}
        with open(filename, "w") as f:
            json.dump(data, f)
    else:
        if reset:
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
        "private-key-enc": private_key_enc.hex(),
        "chaincode": chaincode.hex(),
        "public-key": public_key.hex(),
    }
    
    data["m"] = entry
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)

    print(f"created wallet file: {filename}")
    return entry
def private_key_enc(private_key: bytes) -> bytes:
    """Encrypt private key (currently just hex encoding)."""
    return private_key

parser = argparse.ArgumentParser()
parser.add_argument("name", help="Wallet name")
parser.add_argument("-s", "--seed", type=lambda s: bytes.fromhex(s), help="Seed value as hex string (without 0x)")
parser.add_argument("-m", "--mnemonic", nargs='+', help="BIP39 mnemonic phrase (24 words). Words may be separated by spaces without quoting")
parser.add_argument("--passphrase", default="", help="Optional BIP39 passphrase (separate from encryption password)")
parser.add_argument("password", help="Private key encryption password")
parser.add_argument("-r", "--reset", action="store_true", help="Reset the wallet file if it already exists")
args = parser.parse_args()

if args.seed is None and args.mnemonic is None:
    parser.error("Either seed value (-s/--seed) or mnemonic phrase (-m/--mnemonic) is required")

if args.seed is not None and args.mnemonic is not None:
    parser.error("Cannot specify both seed and mnemonic phrase")

if args.mnemonic:
    mnemonic_phrase = ' '.join(args.mnemonic)
    seed = mnemonic_to_seed(mnemonic_phrase, args.passphrase)
else:
    seed = args.seed

print()
print("Name:", args.name)
if args.mnemonic:
    # display obscured mnemonic
    print("Mnemonic: " + "*" * len(' '.join(args.mnemonic)))
    if args.passphrase:
        print("Passphrase: (hidden)")
else:
    print("Seed:", seed.hex()[:16] + "...")
print("I wont print password, what did you expect ?")
print("Reset:", args.reset)
print()


curve = SECP256k1
curve_order = curve.order

private_key, chaincode = seed_to_master_key(seed)
public_key = private_key_to_public_key(private_key, curve_order)
private_key_enc_result = private_key_enc(private_key)

write_wallet_data(args.name, private_key_enc_result, chaincode, public_key, args.reset)
