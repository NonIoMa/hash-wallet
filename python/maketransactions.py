import hashlib
import base58
import ecdsa
import argparse

### ETC FUNCTIONS
def sha256(data):
    return hashlib.sha256(data).digest()

def double_sha256(data):
    return sha256(sha256(data))

def ripemd160(data):
    h = hashlib.new('ripemd160')
    h.update(data)
    return h.digest()

def hash160(data):
    return ripemd160(sha256(data))

def little_endian(hex_str):
    return bytes.fromhex(hex_str)[::-1].hex()

def get_hex_varint(n):
    if n < 0xfd:
        return n.to_bytes(1,'little').hex()
    elif n <= 0xffff:
        return "fd" + n.to_bytes(2,'little').hex()
    elif n <= 0xffffffff:
        return "fe" + n.to_bytes(4,'little').hex()
    else:
        return "ff" + n.to_bytes(8,'little').hex()

def parse_inputs(inputs_str):
    """
    [txid:vout:address,txid:vout:address]
    -> [{'txid':..., 'vout':..., 'address':...}]
    """

    inputs_str = inputs_str.strip("[]")

    result = []

    for item in inputs_str.split(","):
        txid, vout, address = item.split(":")
        result.append({
            "txid": txid,
            "vout": int(vout),
            "address": address
        })

    return result

def parse_outputs(outputs_str):
    """
    [address:amount,address:amount]
    -> [{'address':..., 'amount':...}]
    """

    outputs_str = outputs_str.strip("[]")

    result = []

    for item in outputs_str.split(","):
        address, amount = item.split(":")
        result.append({
            "address": address,
            "amount": int(amount)
        })

    return result
def parse_password(password_str):
    result = []

    for item in password_str.split(","):
        address, amount = item.split(":")
        result.append({
            "address": address,
            "amount": int(amount)
        })
# ADDRESS => PUBLIC_KEY
def address_to_scriptpubkey(address):

    decoded = base58.b58decode_check(address)
    pubkey_hash = decoded[1:]

    script = bytes.fromhex("76a914") + pubkey_hash + bytes.fromhex("88ac")
    return script.hex()

# SIGN TX
def sign_tx(privkey_hex, tx_hash):

    priv_bytes = bytes.fromhex(privkey_hex)
    sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)

    sig = sk.sign_digest(tx_hash, sigencode=ecdsa.util.sigencode_der)
    sig += b"\x01"  # SIGHASH_ALL

    return sig.hex()

# MAKE SCRIPT
def build_scriptsig(signature_hex, pubkey_hex):

    sig_push = get_hex_varint(len(signature_hex)//2)
    pub_push = get_hex_varint(len(pubkey_hex)//2)

    return sig_push + signature_hex + pub_push + pubkey_hex

# TX BUILDER
def make_transaction(name, inputs, outputs, version):

    locktime = 0

    txid, vout = inputs.split(":")
    vout = int(vout)

    address, amount = outputs.split(":")
    amount = int(amount)

    # PRIVATE KEY
    privkey = "1" * 64

    # TODO derive pubkey from privkey
    pubkey = "04" + "11"*64

    scriptPubKey = address_to_scriptpubkey(address)

    # Build unsigned tx
    version_hex = version.to_bytes(4,'little').hex()

    input_count = get_hex_varint(1)

    txid_hex = little_endian(txid)

    vout_hex = vout.to_bytes(4,'little').hex()

    script_code = scriptPubKey
    script_len = get_hex_varint(len(script_code)//2)

    sequence = "ffffffff"

    output_count = get_hex_varint(1)

    amount_hex = amount.to_bytes(8,'little').hex()

    scriptpub_len = get_hex_varint(len(scriptPubKey)//2)

    locktime_hex = locktime.to_bytes(4,'little').hex()

    sighash = "01000000"

    tx_for_sig = (
        version_hex +
        input_count +
        txid_hex +
        vout_hex +
        script_len +
        script_code +
        sequence +
        output_count +
        amount_hex +
        scriptpub_len +
        scriptPubKey +
        locktime_hex +
        sighash
    )

    # HASHING
    tx_hash = double_sha256(bytes.fromhex(tx_for_sig))

    # SIGN
    signature = sign_tx(privkey, tx_hash)

    scriptSig = build_scriptsig(signature, pubkey)

    scriptSig_len = get_hex_varint(len(scriptSig)//2)

    # FINAL TX
    final_tx = (
        version_hex +
        input_count +
        txid_hex +
        vout_hex +
        scriptSig_len +
        scriptSig +
        sequence +
        output_count +
        amount_hex +
        scriptpub_len +
        scriptPubKey +
        locktime_hex
    )

    print("Wallet:", name)
    print("RAW TX:\n")
    print(final_tx)

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create and sign raw Bitcoin transaction"
    )
    parser.add_argument(
        "name",
        help="Wallet name"
    )
    parser.add_argument(
        "-i",
        "--inputs",
        required=True,
        help="Inputs format: [txid:vout:address,txid:vout:address]"
    )
    parser.add_argument(
        "-o",
        "--outputs",
        required=True,
        help="Outputs format: [address:amount,address:amount]"
    )
    parser.add_argument(
        "-v",
        "--version",
        type=int,
        default=1,
        help="Transaction version"
    )
    parser.add_argument(
        "-p",
        "--passwords",
        type=str,
        help="passwords to decrypt private keys"
    )
    args = parser.parse_args()
    args.inputs = parse_inputs(args.inputs)
    args.outputs = parse_outputs(args.outputs)
    args.passwords = parse_password(args.passwords)
    return args

def main():

    args = _parse_args()

    make_transaction(
        args.name,
        args.inputs,
        args.outputs,
        args.version
    )


if __name__ == "__main__":
    main()