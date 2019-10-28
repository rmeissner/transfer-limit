import os
import requests
import json
import time
from two1.bitcoin.utils import bytes_to_str
from pywallet.utils import HDPrivateKey, HDKey
from web3 import Web3

mnemonic = os.environ['MNEMONIC']
infura_key = os.environ['INFURA_KEY']

w3 = Web3(Web3.HTTPProvider('https://rinkeby.infura.io/v3/' + infura_key))

master_key = HDPrivateKey.master_key_from_mnemonic(mnemonic)
root_key = HDKey.from_path(master_key, "m/44'/60'/0'/0/0")
sender_address = w3.toChecksumAddress(root_key[-1].public_key.address())
private_key = bytes_to_str(bytes(root_key[-1])[-32:])
DAI_BASE_VALUE = 1000000000000000000

class Call:
  def __init__(self, method, params):
    self.method = method
    self.params = params

class State:
    def __init__(self):
        self.safes = {}
        self.last_module_block = "0x4ca0b0"
        self.last_top_up_block = "0x4ca0b0"

def to_request(call):
    return {
        "id": 1,
        "jsonrpc": "2.0",
        "method": call.method,
        "params": call.params
    }

def rpc_call(calls):
    data = list(map(to_request, calls))
    return requests.post(u'https://rinkeby.infura.io/v3/' + infura_key, data=json.dumps(data)).json()

def check_module(module):
    return rpc_call([
        Call("eth_getStorageAt", [module, "0", "latest"])
    ])[0]["result"] == "0x00000000000000000000000053999abfdc3da7eef573f559440b934258928c41"

state = State()
def update_safes_to_watch():
    response = rpc_call([
        Call("eth_getLogs", [
            {
                "fromBlock": state.last_module_block,
                "topics": [
                    "0xecdf3a3effea5783a3c4c2140e677577666428d44ed9d474a0b3a4c9943f8440"
                ]
            }
        ]),
        Call("eth_blockNumber", [])
    ])
    state.last_module_block = response[1]["result"]
    for result in response[0]["result"]:
        module_address = "0x" + result["data"][26:]
        if (check_module(module_address)):
            state.safes[result["address"]] = module_address
    
def check_for_topup():
    safe_addresses = [ "0x" + k[2:].rjust(64, '0') for k in state.safes ]
    response = rpc_call([
        Call("eth_getLogs", [
            {
                "fromBlock": state.last_top_up_block,
                "address": "0x5592ec0cfb4dbc12d3ab100b257153436a1f0fea",
                "topics": [
                    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                    None,
                    safe_addresses        
                ]
            }
        ]),
        Call("eth_blockNumber", [])
    ])
    safes_to_check = list(set(result["topics"][2][2:] for result in response[0]["result"]))
    calls = [
        Call("eth_call", [{
            "to": "0x5592ec0cfb4dbc12d3ab100b257153436a1f0fea",
            "data": "0x70a08231" + safe
        }, "latest"]) for safe in safes_to_check
    ]
    balances = rpc_call(calls)
    for i, balance in enumerate(balances):
        if (int(balance["result"][2:], 16) / DAI_BASE_VALUE) > 10:
            safe = "0x" + safes_to_check[i][24:]
            module = w3.toChecksumAddress(state.safes[safe])
            nonce = w3.eth.getTransactionCount(sender_address)
            signed_txn = w3.eth.account.sign_transaction({
                "gas": 300000,
                "gasPrice": w3.toWei('10', 'gwei'),
                "to": module, 
                "data": "0x0abcb4250000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013fbe85edc90000", 
                "nonce": nonce
            }, private_key=private_key)
            w3.eth.sendRawTransaction(signed_txn.rawTransaction)
            print("Top up", safe)

    state.last_top_up_block = response[1]["result"]

while(True):
    update_safes_to_watch()
    check_for_topup()
    print(state.__dict__)
    time.sleep(15)

