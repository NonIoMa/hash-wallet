import requests
import json
import os
# ALL JSON FILES OPEN
file = os.path.join(".", f"test.json")
with open(os.path.join(file), "w") as f:
    wallet_data = json.load(f)
for add in wallet_data:
    addresses = wallet_data.get(add).get("address")

for addr in addresses:
    utxo_url = f"https://blockstream.info/api/address/{addr}/utxo"
    tx_url = f"https://blockstream.info/api/address/{addr}/txs"

    utxos = requests.get(utxo_url).json()
    txs = requests.get(tx_url).json()

    print(f"\nAddress: {addr}")

    print("UTXOs:")
    for u in utxos:
        print(u)

    print("\nTransactions:")
    for t in txs:
        print(t["txid"])


    #     "bc1qxdddwxwxh3dllclz529xd4d2vw6dpydteuuunh",
    # "1G8sz429N67fJUsM9gkKJE4cdkJ4ZJYsFy",
    # "1xDDDxqBbSx96bhmX34BPLCyB3vUKzMuj"