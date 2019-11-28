from service.api.ethereum.utils import int_to_hex
from service.api.services.account import sender
from service.api.services.rpc import rpc_call, RpcException
from service.settings import RELAY_SAFE_ADDRESS


def call(address, value=0, data=""):
    data = {
        "from": _relayer(),
        "to": address,
        "value": "0x0" if value == 0 else int_to_hex(value),
        "data": data
    }
    response = rpc_call("eth_call", [data, "latest"])
    result = response.get("result")
    if not result:
        raise RpcException(response.get("error"))
    return result


def _relayer():
    if RELAY_SAFE_ADDRESS:
        return RELAY_SAFE_ADDRESS
    else:
        return sender