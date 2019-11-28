
import json
import requests

from service.settings import RPC_ENDPOINT


class RpcException(Exception):
    pass


def _request_headers():
    return {
        "Content-Type": "application/json; UTF-8",
    }


def rpc_call(method, params):
    data = {
        "id": 1,
        "jsonrpc": "2.0",
        "method": method,
        "params": params
    }
    return requests.post(RPC_ENDPOINT, data=json.dumps(data)).json()


def rpc_batch(calls):
    data = [{
        "id": index,
        "jsonrpc": "2.0",
        "method": call[0],
        "params": call[1]
    } for index, call in enumerate(calls) ]
    return requests.post(RPC_ENDPOINT, data=json.dumps(data)).json()


def rpc_result(method, param):
    return rpc_call(method, param)["result"]

