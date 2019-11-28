import rlp
from two1.bitcoin.utils import bytes_to_str

from service.api.ethereum.transactions import Transaction
from service.api.ethereum.utils import parse_int_or_hex, int_to_hex, parse_as_bin
from service.api.services.account import sender, signing_key
from service.api.services.rpc import rpc_result, rpc_call, RpcException
from service.settings import DEFAULT_GAS_PRICE


def _get_nonce():
    return parse_int_or_hex(rpc_result("eth_getTransactionCount", [sender, "pending"]))


def _estimate_transaction_eoa(address, value=0, data=""):
    data = {
        "from": sender,
        "to": address,
        "value": "0x0" if value == 0 else int_to_hex(value),
        "data": data
    }
    response = rpc_call("eth_estimateGas", [data])
    result = response.get("result")
    if not result:
        raise RpcException(response.get("error"))
    return { 'estimate': parse_int_or_hex(result) }


def _send_transaction_eoa(address, params, value=0, data=""):
    gas = params['estimate']
    gas_price = DEFAULT_GAS_PRICE
    nonce = _get_nonce()
    tx = Transaction(nonce, gas_price, gas, address, value, parse_as_bin(data)).sign(signing_key)
    response = rpc_call("eth_sendRawTransaction", ["0x" + bytes_to_str(rlp.encode(tx))])
    result = response.get("result")
    if not result:
        raise RpcException(response.get("error"))
    return result
