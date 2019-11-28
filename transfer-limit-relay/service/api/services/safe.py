import json

import requests
from two1.bitcoin.utils import bytes_to_str

from service.api.ethereum.utils import int_to_hex, parse_as_bin, ecsign
from service.api.services.account import signing_key, sign
from service.api.services.contracts import call
from service.settings import SAFE_RELAY_ENDPOINT, RELAY_SAFE_ADDRESS, GAS_TOKEN_ADDRESS


def _request_headers():
    return {
        "Content-Type": "application/json; UTF-8",
    }


def _estimate_transaction_safe(address, value=0, data=""):
    data = {
        "to": address,
        "value": value,
        "data": data,
        "operation": 0,
        "gasToken": GAS_TOKEN_ADDRESS
    }
    return requests.post("%s/v2/safes/%s/transactions/estimate/" % (SAFE_RELAY_ENDPOINT, RELAY_SAFE_ADDRESS),
                         data=json.dumps(data), headers=_request_headers()).json()


'''
function getTransactionHash(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    )
'''


def _build_get_safe_transaction_hash_payload(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken,
                                             refundReceiver, nonce):
    return "0xd8d11f78" + \
           to[2:].zfill(64) + \
           int_to_hex(value)[2:].zfill(64) + \
           int_to_hex(320)[2:].zfill(64) + \
           int_to_hex(operation)[2:].zfill(64) + \
           int_to_hex(safeTxGas)[2:].zfill(64) + \
           int_to_hex(baseGas)[2:].zfill(64) + \
           int_to_hex(gasPrice)[2:].zfill(64) + \
           gasToken[2:].zfill(64) + \
           refundReceiver[2:].zfill(64) + \
           int_to_hex(nonce)[2:].zfill(64) + \
           int_to_hex(int(len(data[2:]) / 2))[2:].zfill(64) + \
           data[2:]


def _send_transaction_safe(address, params, value=0, data="0x"):
    print(params)
    nonce = params.get('lastUsedNonce') or 0
    payload = _build_get_safe_transaction_hash_payload(
        address, value, data, 0,
        int(params['safeTxGas']), int(params['baseGas']),
        int(params['gasPrice']), params['gasToken'], "0x0000000000000000000000000000000000000000",
        nonce
    )
    print(payload)
    txHash = parse_as_bin(call(RELAY_SAFE_ADDRESS, data=payload))
    print(txHash)
    signature = sign(txHash)
    data = {
        "to": address,
        "value": value,
        "data": data,
        "operation": 0,
        "gasToken": params['gasToken'],
        "safeTxGas": params['safeTxGas'],
        "dataGas": params['baseGas'],
        "gasPrice": params['gasPrice'],
        "nonce": nonce,
        "signatures": [
            {
                "r": signature[1],
                "s": signature[2],
                "v": signature[0]
            }
        ]
    }
    return requests.post("%s//v1/safes/%s/transactions/" % (SAFE_RELAY_ENDPOINT, RELAY_SAFE_ADDRESS),
                         data=json.dumps(data), headers=_request_headers()).json()
