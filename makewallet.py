import os
import json
import hmac
import argparse
import hashlib
import getpass
from mnemonic import Mnemonic
from ecdsa import SECP256k1, SigningKey
from ecdsa.util import number_to_string
from crypto_utils import encrypt_private_key

def private_key_to_public_key(privkey: bytes, curve_order: int) -> bytes:
    """Convert private key to compressed public key."""
    sk = SigningKey.from_string(privkey, curve=SECP256k1)
    vk = sk.get_verifying_key()
    pubkey = b"\x02" + number_to_string(vk.pubkey.point.x(), curve_order)
    if vk.pubkey.point.y() % 2 != 0:
        pubkey = b"\x03" + number_to_string(vk.pubkey.point.x(), curve_order)
    return pubkey

BITCOIN_SEED = b"Bitcoin seed"

def mnemonic_to_seed(mnemonic_phrase: str, passphrase: str = "") -> bytes:
    """Convert BIP39 mnemonic phrase to seed using PBKDF2."""
    mnemonic_generator = Mnemonic("english")
    if not mnemonic_generator.check(mnemonic_phrase):
        raise ValueError("Invalid mnemonic phrase")
    return mnemonic_generator.to_seed(mnemonic_phrase, passphrase)
def seed_to_master_key(seed: bytes):
    """Derive master key and chain code from BIP32 seed."""
    I = hmac.new(BITCOIN_SEED, seed, hashlib.sha512).digest()
    return I[:32], I[32:]  # (privkey, chaincode)
def write_wallet_data(name, private_key_enc_bytes, chaincode, public_key, privacy, reset):
    """Write wallet data to JSON file.

    ``private_key_enc_bytes`` is the encrypted form produced by
    :func:`crypto_utils.encrypt_private_key` and is stored in the wallet as
    hex.
    """
    filename = os.path.join(".", f"{name}.json")
    if not os.path.exists(filename):
        # create an empty wallet file
        data = {"wallet": {}}
        with open(filename, "w") as f:
            json.dump(data, f)
    else:
        if reset:
            # create an empty wallet file
            data = {"wallet": {}}
            with open(filename, "w") as f:
                json.dump(data, f)
        else:
            try:
                with open(filename, "r") as file:
                    data = json.load(file)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON in wallet file {filename}: {e}") from e
            if "wallet" not in data:
                data["wallet"] = {}

    if not isinstance(data, dict):
        raise ValueError(f"wallet file {filename} does not contain an object")

    entry = {
        "private-key-enc": private_key_enc_bytes.hex(),
        "chaincode": chaincode.hex(),
        "public-key": public_key.hex(),
        "privacy": privacy,
    }
    
    data["wallet"]["master"] = entry
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)

    print(f"created wallet file: {filename}")
    return entry
# the actual encryption helper is imported from crypto_utils.  We keep
# this name around for backwards compatibility but its behaviour is just a
# no-op; callers should migrate to :func:`encrypt_private_key` if possible.
def private_key_enc(private_key: bytes) -> bytes:
    """Identity function retained for backwards compatibility."""
    return private_key



def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create a new wallet JSON file")
    parser.add_argument("name", help="Wallet name")
    parser.add_argument(
        "-s", "--seed", type=lambda s: bytes.fromhex(s),
        help="Seed value as hex string (without 0x)")
    parser.add_argument(
        "-m", "--mnemonic", nargs='+',
        help="BIP39 mnemonic phrase (24 words). Words may be separated by spaces without quoting")
    parser.add_argument(
        "--passphrase", default="",
        help="Optional BIP39 passphrase (separate from encryption password)")
    parser.add_argument(
        "password", nargs='?', help="Private key encryption password (will prompt if not provided)")
    parser.add_argument(
        "-p", "--privacy", type=int, default=1,
        help="Privacy level: 0 heavy, 1 light, 2 none (default: 1)")
    parser.add_argument(
        "-r", "--reset", action="store_true",
        help="Reset the wallet file if it already exists")
    args = parser.parse_args()

    if args.seed is None and args.mnemonic is None:
        parser.error("Either seed value (-s/--seed) or mnemonic phrase (-m/--mnemonic) is required")

    if args.seed is not None and args.mnemonic is not None:
        parser.error("Cannot specify both seed and mnemonic phrase")

    if args.password is None:
        args.password = getpass.getpass("Enter encryption password: ")

    if args.seed is not None and len(args.seed) != 64:
        parser.error("Seed must be 64 bytes (128 hex characters)")

    return args


def main() -> None:
    args = _parse_args()

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
    print("Privacy:", args.privacy)
    print("I wont print password, what did you expect ?")
    print("Reset:", args.reset)
    print()

    curve = SECP256k1
    curve_order = curve.order

    private_key, chaincode = seed_to_master_key(seed)
    public_key = private_key_to_public_key(private_key, curve_order)
    # encrypt master private key using the provided password
    private_key_enc_result = encrypt_private_key(private_key, args.password)

    write_wallet_data(args.name, private_key_enc_result, chaincode, public_key, args.privacy, args.reset)


if __name__ == "__main__":
    main()
