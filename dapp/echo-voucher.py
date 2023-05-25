# Copyright 2022 Cartesi Pte. Ltd.
#
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use
# this file except in compliance with the License. You may obtain a copy of the
# License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.

from os import environ
import traceback
import logging
import requests
import json
from eth_abi import decode, encode
import web3

logging.basicConfig(level="INFO")
logger = logging.getLogger(__name__)

rollup_server = environ["ROLLUP_HTTP_SERVER_URL"]
logger.info(f"HTTP rollup_server url is {rollup_server}")

w3 = web3.Web3()


###
# Aux Functions 

def str2hex(string):
    """
    Encode a string as an hex string
    """
    return binary2hex(str2binary(string))

def str2binary(string):
    """
    Encode a string as an binary string
    """
    return string.encode("utf-8")

def binary2hex(binary):
    """
    Encode a binary as an hex string
    """
    return "0x" + binary.hex()

def hex2binary(hexstr):
    """
    Decodes a hex string into a regular byte string
    """
    return bytes.fromhex(hexstr[2:])

def hex2str(hexstr):
    """
    Decodes a hex string into a regular string
    """
    return hex2binary(hexstr).decode("utf-8")

def send_voucher(voucher):
    send_post("voucher",voucher)

def send_report(report):
    send_post("report",report)

def send_post(endpoint,json_data):
    response = requests.post(rollup_server + f"/{endpoint}", json=json_data)
    logger.info(f"/{endpoint}: Received response status {response.status_code} body {response.content}")


###
# Portal Deposit headers

# Default header for ERC-20 transfers coming from the Portal, which corresponds
#   to the Keccak256-encoded string "ERC20_Transfer", as defined at
#   https://github.com/cartesi/rollups/blob/v0.8.2/onchain/rollups/contracts/facets/ERC20PortalFacet.sol
ERC20_DEPOSIT_HEADER = hex2binary(w3.keccak(b'ERC20_Transfer').hex())

# Default header for ERC-721 transfers coming from the Portal, which corresponds
#   to the Keccak256-encoded string "ERC721_Transfer", as defined at
#   https://github.com/cartesi/rollups/blob/v0.8.2/onchain/rollups/contracts/facets/ERC721PortalFacet.sol
ERC721_DEPOSIT_HEADER = hex2binary(w3.keccak(b'ERC721_Transfer').hex())

# Default header for Ether transfers coming from the Portal, which corresponds
# to the Keccak256-encoded string "Ether_Transfer", as defined at
#   https://github.com/cartesi/rollups/blob/v0.8.2/onchain/rollups/contracts/facets/EtherPortalFacet.sol
ETHER_DEPOSIT_HEADER = hex2binary(w3.keccak(b'Ether_Transfer').hex())


###
# Selector of functions for solidity <contract>.call(<payload>)

# ERC-20 contract function selector to be called during the execution of a voucher,
#   which corresponds to the first 4 bytes of the Keccak256-encoded result of "transfer(address,uint256)"
ERC20_TRANSFER_FUNCTION_SELECTOR = hex2binary(w3.keccak(b'transfer(address,uint256)')[:4].hex())

# ERC-721 contract function selector to be called during the execution of a voucher,
#   which corresponds to the first 4 bytes of the Keccak256-encoded result of "safeTransferFrom(address,address,uint256)"
ERC721_SAFETRANSFER_FUNCTION_SELECTOR = hex2binary(w3.keccak(b'safeTransferFrom(address,address,uint256)')[:4].hex())

# EtherPortalFacet contract function selector to be called during the execution of a voucher,
#   which corresponds to the first 4 bytes of the Keccak256-encoded result of "etherWithdrawal(bytes)", as defined at
#   https://github.com/cartesi/rollups/blob/v0.8.2/onchain/rollups/contracts/interfaces/IEtherPortal.sol
ETHER_WITHDRAWAL_FUNCTION_SELECTOR = hex2binary(w3.keccak(b'etherWithdrawal(bytes)')[:4].hex())


###
# Decode Deposit Aux Functions 

def decode_erc20_deposit(binary):
    decoded = decode(['bytes32', 'address', 'address', 'uint256', 'bytes'], binary)
    erc20_deposit = {
        "depositor":decoded[1],
        "token_address":decoded[2],
        "amount":decoded[3],
        "data":decoded[4],
    }
    logger.info(erc20_deposit)
    return erc20_deposit

def decode_erc721_deposit(binary):
    decoded = decode(['bytes32', 'address', 'address', 'address', 'uint256', 'bytes'], binary)
    erc721_deposit = {
        "token_address":decoded[1],
        "operator":decoded[2],
        "depositor":decoded[3],
        "token_id":decoded[4],
        "data":decoded[5],
    }
    logger.info(erc721_deposit)
    return erc721_deposit

def decode_ether_deposit(binary):
    decoded = decode(['bytes32', 'address', 'uint256', 'bytes'], binary)
    ether_deposit = {
        "depositor":decoded[1],
        "amount":decoded[2],
        "data":decoded[3],
    }
    logger.info(ether_deposit)
    return ether_deposit


###
# Create Voucher Aux Functions 

def create_erc20_transfer_voucher(token_address,receiver,amount):
    # Function to be called in voucher [token_address].transfer([address receiver],[uint256 amount])
    data = encode(['address', 'uint256'], [receiver,amount])
    voucher_payload = binary2hex(ERC20_TRANSFER_FUNCTION_SELECTOR + data)
    voucher = {"address": token_address, "payload": voucher_payload}
    return voucher

def create_erc721_safetransfer_voucher(token_address,sender,receiver,id):
    # Function to be called in voucher [token_address].transfer([address sender],[address receiver],[uint256 id])
    data = encode(['address', 'address', 'uint256'], [sender,receiver,id])
    voucher_payload = binary2hex(ERC721_SAFETRANSFER_FUNCTION_SELECTOR + data)
    voucher = {"address": token_address, "payload": voucher_payload}
    return voucher

def create_ether_withdrawal_voucher(receiver,amount):
    # Function to be called in voucher [rollups_address].etherWithdrawal(bytes) where bytes is ([address receiver],[uint256 amount])
    data = encode(['address', 'uint256'], [receiver,amount])
    data2 = encode(['bytes'],[data])
    voucher_payload = binary2hex(ETHER_WITHDRAWAL_FUNCTION_SELECTOR + data2)
    voucher = {"address": rollup_address, "payload": voucher_payload}
    return voucher


###
#  Generate Voucher Functions 

def process_deposit_and_generate_voucher(payload):
    binary = hex2binary(payload)
    input_header = decode(['bytes32'], binary)[0]
    logger.info(f"header {input_header}")
    voucher = None

    if input_header == ERC20_DEPOSIT_HEADER:
        erc20_deposit = decode_erc20_deposit(binary)

        # send deposited erc20 back to depositor
        token_address = erc20_deposit["token_address"]
        receiver = erc20_deposit["depositor"]
        amount = erc20_deposit["amount"]

        voucher = create_erc20_transfer_voucher(token_address,receiver,amount)

    elif input_header == ERC721_DEPOSIT_HEADER:
        erc721_deposit = decode_erc721_deposit(binary)

        # send deposited erc721 back to depositor
        token_address = erc721_deposit["token_address"]
        receiver = erc721_deposit["depositor"]
        token_id = erc721_deposit["token_id"]

        voucher = create_erc721_safetransfer_voucher(token_address,rollup_address,receiver,token_id)

    elif input_header == ETHER_DEPOSIT_HEADER:
        ether_deposit = decode_ether_deposit(binary)

        # send deposited ether back to depositor
        receiver = ether_deposit["depositor"]
        amount = ether_deposit["amount"]

        voucher = create_ether_withdrawal_voucher(receiver,amount)

    else:
        pass

    return voucher

def get_voucher_from_input(payload):
    str_payload = hex2str(payload)
    voucher = json.loads(str_payload)
    return voucher


###
#  Aux Functions to Generate Voucher from json with abi, function name and parameters


def process_and_validate_json(payload):
    str_payload = hex2str(payload)
    json_data = json.loads(str_payload)
    logger.info(f"json_data {json_data}")

    if not json_data.get("address"):
        raise Exception('Json object must include "address" key with the contract address the voucher will execute')
    if not json_data.get("functionName"):
        raise Exception('Json object must include "functionName" key with the contract function name the voucher will execute')
    if not json_data.get("parameters"):
        raise Exception('Json object must include "parameters" key with the function parameters list')
    if not json_data.get("abi"):
        raise Exception('Json object must include "abi" key with the contract abi')

    contract_address = str(json_data["address"])
    function_name = str(json_data["functionName"])
    parameters = list(json_data["parameters"])
    abi = list(json_data["abi"])

    function_abi_list = list(filter(lambda entry: entry['type'] == 'function' and entry['name'] == function_name and len(entry['inputs']) == len(parameters), abi))
    logger.info(f"function_abi_list {function_abi_list}")
    if len(function_abi_list) != 1:
        raise Exception('Could not find the abi for the selected function')
    
    function_abi = function_abi_list[0]
    parameters_type = list(map(lambda i: i['type'],function_abi['inputs']))
    function_declaration = f"{function_name}({','.join(parameters_type)})"
    function_selector = hex2binary(w3.keccak(str2binary(function_declaration))[:4].hex())

    return {
        "contract_address":contract_address,
        "parameters":parameters,
        "parameters_type":parameters_type,
        "function_selector":function_selector
    }

def generate_voucher_from_json(payload):
    processed_input = process_and_validate_json(payload)

    data = encode(processed_input["parameters_type"], processed_input["parameters"])
    voucher_payload = binary2hex(processed_input["function_selector"] + data)
    voucher = {"address": processed_input["contract_address"], "payload": voucher_payload}

    return voucher

###
# handlers

def handle_advance(data):
    logger.info(f"Received advance request data {data}")

    try:
        payload = data["payload"]
        voucher = None

        # Check whether an input was sent by the Portal,
        #   which is where all deposits must come from
        if data["metadata"]["msg_sender"] == rollup_address:
            voucher = process_deposit_and_generate_voucher(payload)
        else:
            # Otherwise, payload should be a json with the voucher ready to be sent
            voucher = get_voucher_from_input(payload)
        
        if voucher:
            logger.info(f"voucher {voucher}")
            send_voucher(voucher)

        return "accept"

    except Exception as e:
        msg = f"Error {e} processing data {data}"
        logger.error(f"{msg}\n{traceback.format_exc()}")
        send_report({"payload": str2hex(msg)})
        return "reject"

def handle_inspect(data):
    logger.info(f"Received inspect request data {data}")

    try:
        payload = data["payload"]

        voucher = generate_voucher_from_json(payload)
        report_payload = str2hex(json.dumps(voucher))
        logger.info(f"report_payload {report_payload}")

        logger.info(f"voucher {voucher}")
        send_report({"payload": report_payload})

        return "accept"

    except Exception as e:
        msg = f"Error {e} processing data {data}"
        logger.error(f"{msg}\n{traceback.format_exc()}")
        send_report({"payload": str2hex(msg)})
        return "reject"


handlers = {
    "advance_state": handle_advance,
    "inspect_state": handle_inspect,
}


###
# Main Loop

finish = {"status": "accept"}
rollup_address = None

while True:
    logger.info("Sending finish")
    response = requests.post(rollup_server + "/finish", json=finish)
    logger.info(f"Received finish status {response.status_code}")
    if response.status_code == 202:
        logger.info("No pending rollup request, trying again")
    else:
        rollup_request = response.json()
        data = rollup_request["data"]
        if "metadata" in data:
            metadata = data["metadata"]
            if metadata["epoch_index"] == 0 and metadata["input_index"] == 0:
                rollup_address = metadata["msg_sender"]
                logger.info(f"Captured rollup address: {rollup_address}")
                continue
        handler = handlers[rollup_request["request_type"]]
        finish["status"] = handler(rollup_request["data"])
