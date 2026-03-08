import requests
import json
import os
import argparse

parser = argparse.ArgumentParser(description="Check UTXOs for all addresses in a wallet")
parser.add_argument("name", help="Wallet name")

args = parser.parse_args()


file = os.path.join("..", "wallets", args.name + ".json")

with open(file, "r") as f:
    wallet_data = json.load(f)

addresses = wallet_data["wallet"]["addresses"]

for addrEL in addresses:
    address = addrEL["address"]

    print(f"Checking {address}")

    utxo_url = f"https://blockstream.info/api/address/{address}/utxo"
    tx_url = f"https://blockstream.info/api/address/{address}/txs"

    utxos = requests.get(utxo_url).json()
    txs = requests.get(tx_url).json()

    addrEL["UTXO"] = utxos
    addrEL["transactions"] = [t["txid"] for t in txs]

with open(file, "w") as f:
    json.dump(wallet_data, f, indent=2)
    