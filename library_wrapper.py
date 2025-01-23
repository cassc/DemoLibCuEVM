"""
library wrapper to maintain state of EVM instances and run tx on them
"""

from binascii import hexlify
import sys
import ctypes
import json
import copy
from pprint import pformat, pprint
import time
import pre_state_conversion as conv
from pre_state_conversion import Account, PreState
from post_state_conversion import PostState, PostStates, PostAccount
from conversion import to_ctype_byte_array
from logger import log
from utils import *

# Add the directory containing your .so file to the Python path
# sys.path.append("../build/")
sys.path.append("./binary/")

import libcuevm  # Now you can import your module as usual

EMPTY_CTYPE_ARRAY = (ctypes.c_uint8 * 0)()

def update_pre_accounts(preState: PreState, postState: PostState, sender: bytes):
    accounts = {}
    print("sender ", sender)
    senderNonce = None
    for i in range(preState.preAccountsSize):
        account = preState.preAccounts[i]
        accounts[bytes(account.address)] =  account

    if postState.postAccountsSize > 0:
        postAccounts = ctypes.cast(postState.postAccounts, ctypes.POINTER(PostAccount * postState.postAccountsSize)).contents

        for i in range(postState.postAccountsSize):
            postAccount = postAccounts[i]
            address = bytes(postAccount.address)
            oldAccount = accounts.get(address)
            storageSize = postAccount.storageSize
            if sender == address:
                senderNonce = to_ctype_byte_array(bytes(postAccount.nonce))

            if oldAccount:
                log.debug("updating account %s nonce, balance, storage. storageSize: %s -> %s", address, oldAccount.storageSize, storageSize)
                log.debug("Updating nonce from %s to %s", bytes(oldAccount.nonce).hex(), bytes(postAccount.nonce).hex())
                ctypes.memmove(oldAccount.nonce, postAccount.nonce, ctypes.sizeof(postAccount.nonce))
                log.debug("Updating balance from %s to %s", bytes(oldAccount.balance).hex(), bytes(postAccount.balance).hex())
                ctypes.memmove(oldAccount.balance, postAccount.balance, ctypes.sizeof(postAccount.balance))
                log.debug("Updating storage size from %s to %s", oldAccount.storageSize, storageSize)
                oldAccount.storageSize = storageSize

                if storageSize > 0:
                    ctypes.memmove(oldAccount.storage, postAccount.storage, ctypes.sizeof(postAccount.storage))
                # code does not exist in the post state, so we don't override it
            else:
                account = Account()
                log.debug("creating new account %s with storageSize: %s", bytes(address)[12:].hex(), storageSize)
                ctypes.memmove(account.nonce, postAccount.nonce, ctypes.sizeof(postAccount.nonce))
                ctypes.memmove(account.balance, postAccount.balance, ctypes.sizeof(postAccount.balance))
                ctypes.memmove(account.address, postAccount.address, ctypes.sizeof(postAccount.address))
                if storageSize > 0:
                    ctypes.memmove(account.storage, postAccount.storage, ctypes.sizeof(postAccount.storage))
                account.storageSize = storageSize
                account.codeSize = 0
                accounts[address] = account

    accounts = list(accounts.values())
    preState.preAccounts = (Account * len(accounts))(*accounts)
    preState.preAccountsSize = len(accounts)
    return senderNonce


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

    def update_persistent_state(self, post):
        size = post.postStatesSize
        if size == 0:
            return
        states = post.postStates

        sender = bytes(conv.hex_to_evm_word_bytes(self.sender))
        for i in range(size):
            post_state = states[i]
            sender_nonce = update_pre_accounts(self.instances[i], post_state, sender)

            if sender_nonce is not None:
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
        num_instances = len(self.instances)
        instances = (conv.PreState * num_instances)()
        log.debug("run_transactions, num instances: %s", num_instances)
        for i in range(num_instances):
            instances[i] = self.instances[i]
            for j in range(instances[i].preAccountsSize):
                account = instances[i].preAccounts[j]
                address = hexlify(bytes(account.address)[12:]).decode()
                codeSize = account.codeSize
                code = hexlify(bytes(account.code[:codeSize])).decode()
                log.debug("account code: address %s codeSize %s code %s", address, codeSize, code)

        mem_view = libcuevm.run_dict(instances, skip_trace_parsing)
        p_results = PostStates.from_buffer_copy(mem_view)

        for i in range(num_instances):
            log.debug(f"Instance: {i} result number of accounts:  {p_results.postStates[i].postAccountsSize}")
            for j in range(p_results.postStates[i].postAccountsSize):
                account = p_results.postStates[i].postAccounts[j]
                address = hexlify(bytes(account.address)[12:]).decode()
                log.debug("account code: address %s", address)

        if measure_performance:
            time_end = time.time()
            print(f"Time taken: {time_end - time_start} seconds")
        self.update_persistent_state(p_results)
        r = self.post_process_trace(p_results)

        # todo: need to free post_states

        return r

    # post process the trace to detect integer bugs and simplify the distance
    def post_process_trace(self, post):
        size = post.postStatesSize
        if size < 1:
            print("Skipping post processing")
            return []
        final_trace = []


        for i in range(size):
            tx_trace = post.postStates[i].trace
            branches = []
            events = []
            storage_write = []
            bugs = []

            # todo_cl fix this
            print(ctypes.alignment(PostStates)) # => 8
            print(ctypes.sizeof(PostStates))  # => 16

            log.debug("post_process_trace branchesSize %s eventsSize %s callsSize %s", tx_trace.branchesSize, tx_trace.eventsSize, tx_trace.callsSize)



            for i in range(tx_trace.branchesSize):

                branch = tx_trace.branches[i]
                branches.append(
                    EVMBranch(
                        pc_src=branch.pcSrc,
                        pc_dst=branch.pcDst,
                        pc_missed=branch.pcMissed,
                        distance=branch.distance, # todo_cl may need to convert to number
                    )
                )

            for i in range(tx_trace.eventsSize):
                event = tx_trace.events[i]
                if event.op == OP_SSTORE:
                    storage_write.append(
                        EVMStorageWrite(
                            pc=event.pc,
                            key=event.stack[0:32], # todo_cl may need conversion
                            value=event.stack[32:64],
                        )
                    )
                else:
                    events.append(
                        TraceEvent(
                            pc=event.pc,
                            opcode=event.op,
                            operand_1=event.stack[0:32], # todo_cl convert to number
                            operand_2=event.stack[32:64],
                            result=event.res, # convert to number
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
            for i in range(tx_trace.callsSize):
                call = tx_trace.calls[i]
                all_call.append(
                    EVMCall(
                        pc=call.pc,
                        opcode=call.op,
                        _from=call.sender,
                        _to=call.receiver,
                        value=call.value, # todo_cl to number
                        result=call.success
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
                log.debug("target_code %s %s", hexlify(bytes(account.code[:target_code_size])).decode(), target_code_size)
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
        log.debug("tx_data %s", tx_data, extra={'format': pformat})
        if len(tx_data) < len(self.instances):
            tx_data = tx_data + [tx_data[-1]] * (len(self.instances) - len(tx_data))
        if len(tx_data) > len(self.instances):
            tx_data = tx_data[: len(self.instances)]
        # print (f"tx_data_rebuilt {tx_data}")
        for i in range(len(tx_data)):
            # todo update all callers of self.instances as it's no longer a dict
            data = conv.hex_to_bytes(tx_data[i]["data"][0])
            self.instances[i].transaction.data = data
            self.instances[i].transaction.dataSize = len(data) # don't use cpp pointer directly, eg len(bytes(self.instances[i].transaction.data))
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
