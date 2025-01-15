"""
library wrapper to maintain state of EVM instances and run tx on them
"""

from binascii import hexlify
import sys
import ctypes
import json
import copy
from pprint import pprint
import time
import conversion as conv
from logger import log
from utils import *

# Add the directory containing your .so file to the Python path
# sys.path.append("../build/")
sys.path.append("./binary/")

import libcuevm  # Now you can import your module as usual

EMPTY_CTYPE_ARRAY = (ctypes.c_uint8 * 0)()

class CuEVMLib:
    def __init__(
        self,
        source_file,
        num_instances,
        config=None,
        contract_name=None,
        detect_bug=False,
        sender="0x1111111111111111111111111111111111111111",
        contract_bin_runtime=None,
    ):
        self.initiate_instance_data(
            source_file,
            num_instances,
            config,
            contract_name,
            detect_bug,
            contract_bin_runtime,
        )
        self.sender = sender

    def update_persistent_state(self, json_result):
        trace_values = json_result
        log.debug("trace value result")
        log.debug(json_result)

        if trace_values is None or trace_values.get("post") is None:
            return
        for i in range(len(trace_values.get("post"))):
            post_state = trace_values.get("post")[i].get("state")
            if not post_state:
                print("BAD STATE: No post state skipping updating state")
                continue
            # todo_cl maybe should not replace the state
            conv.replace_pre_accounts(self.instances[i], post_state)

            sender_nonce = post_state.get(self.sender).get("nonce") # is a number, better use native bytes
            if sender_nonce:
                sender_nonce = conv.hex_to_evm_word_bytes(f'{sender_nonce:0x}')
                self.instances[i].transaction.nonce = sender_nonce
            else:
                print(f"BAD STATE: Sender nonce not found in post state")



    ## 1. run transactions on the EVM instances
    ## 2. update the persistent state of the EVM instances
    ## 3. return the simplified trace during execution
    def run_transactions(self, tx_data, skip_trace_parsing=False, measure_performance=False):
        # print("run_transactions")
        # pprint(tx_data)
        self.build_instance_data(tx_data)
        # self.print_instance_data()
        # print ("before running")
        if measure_performance:
            time_start = time.time()
        instances = (conv.PreState * len(self.instances))()
        for i in range(len(self.instances)):
            instances[i] = self.instances[i]
        result_state = libcuevm.run_dict(instances, skip_trace_parsing)
        if measure_performance:
            time_end = time.time()
            print(f"Time taken: {time_end - time_start} seconds")
        self.update_persistent_state(result_state)
        return self.post_process_trace(result_state)

    # post process the trace to detect integer bugs and simplify the distance
    def post_process_trace(self, json_result):
        if json_result is None or json_result.get("post") is None:
            print("Skipping post processing")
            return []
        final_trace = []
        # print("\ntrace\n")
        # pprint(trace)
        for i in range(len(json_result.get("post"))):
            tx_trace = json_result.get("post")[i].get("trace")
            # print("tx trace")
            # pprint(tx_trace)
            branches = []
            events = []
            storage_write = []
            bugs = []
            for branch in tx_trace.get("branches", [])[3:]:
                branches.append(
                    EVMBranch(
                        pc_src=branch.get("pc_src"),
                        pc_dst=branch.get("pc_dst"),
                        pc_missed=branch.get("pc_missed"),
                        distance=int(branch.get("distance"), 16),
                    )
                )

            for event in tx_trace.get("events", []):
                if event.get("opcode") == OP_SSTORE:
                    storage_write.append(
                        EVMStorageWrite(
                            pc=event.get("pc"),
                            key=event.get("operand_1"),
                            value=event.get("operand_2"),
                        )
                    )
                else:
                    events.append(
                        TraceEvent(
                            pc=event.get("pc"),
                            opcode=event.get("op"),
                            operand_1=int(event.get("operand_1"), 16),
                            operand_2=int(event.get("operand_2"), 16),
                            result=int(event.get("res"), 16),
                        )
                    )
                    if self.detect_bug:
                        current_event = events[-1]
                        if (current_event.opcode == OPADD and current_event.operand_1 + current_event.operand_2 >= 2**256):
                            bugs.append(EVMBug(current_event.pc, current_event.opcode, "integer overflow"))
                        elif (current_event.opcode == OPMUL and current_event.operand_1 * current_event.operand_2 >= 2**256):
                            bugs.append(EVMBug(current_event.pc, current_event.opcode, "integer overflow"))
                        elif (current_event.opcode == OPSUB and current_event.operand_1 < current_event.operand_2):
                            bugs.append(EVMBug(current_event.pc, current_event.opcode, "integer underflow"))
                        elif (current_event.opcode == OPEXP and current_event.operand_1 ** current_event.operand_2 >= 2**256):
                            bugs.append(EVMBug(current_event.pc, current_event.opcode, "integer overflow"))
                        elif current_event.opcode == OP_SELFDESTRUCT:
                            bugs.append(EVMBug(current_event.pc, current_event.opcode, "selfdestruct"))

            all_call = []
            for call in tx_trace.get("calls", []):
                all_call.append(
                    EVMCall(
                        pc=call.get("pc"),
                        opcode=call.get("op"),
                        _from=call.get("sender"),
                        _to=call.get("receiver"),
                        value=int(call.get("value"), 16),
                        result=call.get("success")
                    )
                )
                if self.detect_bug:
                    if all_call[-1].value > 0 and all_call[-1].pc != 0:
                        bugs.append(
                            EVMBug(
                                pc=all_call[-1].pc,
                                opcode=all_call[-1].opcode,
                                bug_type="Leaking Ether",
                            )
                        )

            final_trace.append(
                {
                    "branches": branches,
                    "events": events,
                    "calls": all_call,
                    "storage_write": storage_write,
                    "bugs": bugs,
                }
            )


        return final_trace

    ## initiate num_instances clones of the initial state
    def initiate_instance_data(
        self,
        source_file,
        num_instances,
        config,
        contract_name=None,
        detect_bug=False,
        contract_bin_runtime=None,
    ):
        # todo update this to load the PreState
        # and merge the default one with the user provided one
        with open("configurations/default.json") as f:
            default_config_json = json.load(f)
            target_address = default_config_json["target_address"]
        # print(default_config)
        self.detect_bug = detect_bug
        # tx_sequence_list
        with open(config) as f:
            tx_sequence_config = json.load(f)
        if contract_name is None:
            self.contract_name = tx_sequence_config.get("contract_name")
        else:
            self.contract_name = contract_name
        # print(f" source file {source_file} contract_name {self.contract_name} \n\n")
        self.contract_instance, self.ast_parser = compile_file(
            source_file, self.contract_name
        )
        if self.contract_instance is None:
            print("Error in compiling the contract {self.contract_name} {source_file}")
            return
        if contract_bin_runtime is None:
            contract_bin_runtime = self.contract_instance.get("binary_runtime")
        # the merged config fields : "env", "pre" (populated with code), "transaction" (populated with tx data and value)
        pre_env = tx_sequence_config.get("pre", {})
        default_config_json["pre"].update(pre_env) # todo

        new_test = conv.load_prestate_from_json(default_config_json)


        target_code = conv.hex_to_bytes(contract_bin_runtime)
        target_code_size = len(target_code)
        target_storage_bytes = b""
        target_storage_size = 0

        for key, value in tx_sequence_config.get("storage", {}).items():
            target_storage_bytes += bytes(conv.hex_to_evm_word_bytes(key))
            target_storage_bytes += bytes(conv.hex_to_evm_word_bytes(value))
            target_storage_size += 1
        target_storage_bytes = (ctypes.c_uint8 * len(target_storage_bytes))(*target_storage_bytes) if target_storage_size > 0 else EMPTY_CTYPE_ARRAY

        target_pre_account_updated = False
        for i in range(new_test.preAccountsSize):
            account = new_test.preAccounts[i]
            if bytes(account.address) == bytes(conv.hex_to_evm_word_bytes(target_address)):
                account.code = target_code
                account.codeSize = target_code_size
                account.storage = target_storage_bytes
                account.storageSize = target_storage_size
                target_pre_account_updated = True
        if not target_pre_account_updated:
            raise ValueError("target account not in the pre state of tx_sequence_config")

        new_test.transaction.to = conv.hex_to_evm_word_bytes(target_address)

        self.instances = [copy.deepcopy(new_test) for _ in range(num_instances)]

    def print_instance_data(self):
        for idx, instance in enumerate(self.instances):
            print(f"\n\n Instance data {idx}\n\n")
            size = instance.preAccountsSize
            for i in range(size):
                account = instance.preAccounts[i]
                address = "0x" + hexlify(bytes(account.address)[12:]).decode().upper()
                code = "0x" + hexlify(bytes(account.code[:account.codeSize])).decode().upper()
                print("address", address)
                print("code", code)
                print("codeSize", account.codeSize)


    ## build instances data from new tx data
    ## tx_data is a list of tx data
    def build_instance_data(self, tx_data):
        if len(tx_data) < len(self.instances):
            tx_data = tx_data + [tx_data[-1]] * (len(self.instances) - len(tx_data))
        if len(tx_data) > len(self.instances):
            tx_data = tx_data[: len(self.instances)]
        # print (f"tx_data_rebuilt {tx_data}")
        for i in range(len(tx_data)):
            # todo update all callers of self.instances as it's no longer a dict
            self.instances[i].transaction.data = conv.hex_to_bytes(tx_data[i]["data"][0])
            self.instances[i].transaction.dataSize = len(bytes(self.instances[i].transaction.data))
            self.instances[i].transaction.value = conv.hex_to_evm_word_bytes(tx_data[i]["value"][0])
            if tx_data[i].get("sender"):
                self.instances[i].transaction.sender = conv.hex_to_evm_word_bytes(tx_data[i]["sender"])
            # print("using txdta", bytes(self.instances[i].transaction.data).hex())
            # print("sender", bytes(self.instances[i].transaction.sender))

            # TODO: add other fuzz-able fields


def test_state_change():
    my_lib = CuEVMLib(
        "contracts/state_change.sol",
        2,
        "configurations/state_change.json",
        # contract_bin_runtime="6011602201600460110260005560015561123460015561ffff60ff5500",
    )
    test_case = {
        "function": "increase",
        "type": "exec",
        "input_types": [],
        "input": [],
        "sender": 0,
    }

    tx_1 = {
        "data": get_transaction_data_from_config(
            test_case, my_lib.contract_instance
        ),  # must return an array
        "value": [hex(0)],
    }
    tx_2 = {
        "data": get_transaction_data_from_config(
            test_case, my_lib.contract_instance
        ),  # must return an array
        "value": [hex(0)],
    }

    # for debugging, altering tx2 data
    tx_2["data"] = ["0x12"]
    tx_2["value"] = [hex(10)]
    # for debugging, altering the state 2
    my_lib.instances[1]["pre"]["0xcccccccccccccccccccccccccccccccccccccccc"]["storage"][
        "0x00"
    ] = "0x30"
    my_lib.instances[0]["pre"]["0xcccccccccccccccccccccccccccccccccccccccc"]["storage"][
        "0x00"
    ] = "0x10"
    # my_lib.instances[2]["pre"]["0xcccccccccccccccccccccccccccccccccccccccc"]["storage"][
    #     "0x00"
    # ] = "0x33"
    trace_res = my_lib.run_transactions([tx_1, tx_1])
    # trace_res = my_lib.run_transactions([tx_1])
    print("\n\n trace res \n\n")
    pprint(trace_res)
    print("\n\n Updated instance data \n\n")
    my_lib.print_instance_data()

    trace_res = my_lib.run_transactions([tx_1, tx_2])

    # print("\n\n Updated instance data \n\n")
    my_lib.print_instance_data()


def test_erc20():
    my_lib = CuEVMLib(
        "contracts/erc20.sol",
        2,
        "configurations/erc20.json",
        contract_name="ERC20",
        detect_bug=False,
    )
    test_case = {
        "function": "transfer",
        "type": "exec",
        "input_types": ["address", "uint256"],
        "input": ["0x0000000000000000000000000000000000000001", 512],
        "sender": 0,
    }

    tx_1 = {
        "data": get_transaction_data_from_config(
            test_case, my_lib.contract_instance
        ),  # must return an array
        "value": [hex(512)],
    }
    tx_2 = {
        "data": get_transaction_data_from_config(
            test_case, my_lib.contract_instance
        ),  # must return an array
        "value": [hex(512)],
    }
    trace_res = my_lib.run_transactions([tx_1, tx_2])
    print("\n\n trace res \n\n")
    pprint(trace_res)


def test_branching():
    my_lib = CuEVMLib(
        "contracts/branching.sol",
        2,
        "configurations/test_branching.json",
    )
    test_case_1 = {
        "function": "test_branch",
        "type": "exec",
        "input_types": ["uint256"],
        "input": [12345],
        "sender": 0,
    }
    test_case_2 = {
        "function": "test_branch",
        "type": "exec",
        "input_types": ["uint256"],
        "input": [50],
        "sender": 0,
    }

    tx_1 = {
        "data": get_transaction_data_from_config(test_case_1, my_lib.contract_instance),
        "value": [hex(0)],
    }

    tx_2 = {
        "data": get_transaction_data_from_config(test_case_2, my_lib.contract_instance),
        "value": [hex(0)],
    }
    trace_res = my_lib.run_transactions([tx_1, tx_2])
    print("\n\n trace res \n\n")
    pprint(trace_res)


def test_system_operation():
    my_lib = CuEVMLib(
        "contracts/system_operations.sol",
        1,
        "configurations/system_operation.json",
    )
    test_case = {
        "function": "test_call",
        "type": "exec",
        "input_types": ["address", "uint256"],
        "input": ["0x1000000000000000000000000000000000000000", 0x1],
        "sender": 0,
    }

    tx_1 = {
        "data": get_transaction_data_from_config(test_case, my_lib.contract_instance),
        "value": [hex(1234)],
    }

    trace_res = my_lib.run_transactions([tx_1])
    print("\n\n trace res \n\n")
    pprint(trace_res)

def test_bugs_simple():
    my_lib = CuEVMLib(
        "contracts/test_bugs_simple.sol",
        5000,
        "configurations/default.json",
        contract_name="TestBug",
        detect_bug=True,
    )
    test_case = {
        "function": "bug_combined",
        "type": "exec",
        "input_types": [],
        "input": [],
        "sender": 0,

    }
    # print("instance data")
    # pprint(my_lib.instances)

    tx_1 = {
        "data": get_transaction_data_from_config(test_case, my_lib.contract_instance),
        "value": [hex(0)],
    }

    trace_res = my_lib.run_transactions([tx_1], measure_performance=True, skip_trace_parsing=True)
    print("\n\n trace res \n\n")
    if trace_res is not None and len(trace_res) > 0:
        pprint(trace_res[0])

def test_cross_contract():
    my_lib = CuEVMLib(
        "contracts/cross_contract.sol",
        1,
        "configurations/cross_contract.json",
        detect_bug=True,
    )
    test_case = {
        "function": "underflow",
        "type": "exec",
        "input_types": ["address", "address"],
        "input": [
            "0x1000000000000000000000000000000000000000",
            "0x2000000000000000000000000000000000000000",
        ],
        "value": 300,
        "sender": 0,
        "receiver": "0x1000000000000000000000000000000000000000",
    }

    tx_1 = {
        "data": get_transaction_data_from_config(test_case, my_lib.contract_instance),
        "value": [hex(300)],
    }

    trace_res = my_lib.run_transactions([tx_1])
    print("\n\n trace res \n\n")
    pprint(trace_res)


if __name__ == "__main__":

    # test_system_operation()
    # test_cross_contract()
    # test_bugs_simple()
    test_state_change()
