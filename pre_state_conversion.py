import ctypes
from binascii import hexlify
from logger import log
import copy
from conversion import hex_to_evm_word_bytes, hex_to_bytes, EVMWordStruct

# Define the Env struct
class Env(EVMWordStruct):
    _fields_ = [
        ("currentBaseFee", ctypes.c_uint8 * 32),
        ("currentBeaconRoot", ctypes.c_uint8 * 32),
        ("currentCoinbase", ctypes.c_uint8 * 32),
        ("currentDifficulty", ctypes.c_uint8 * 32),
        ("currentGasLimit", ctypes.c_uint8 * 32),
        ("currentNumber", ctypes.c_uint8 * 32),
        ("currentRandom", ctypes.c_uint8 * 32),
        ("currentTimestamp", ctypes.c_uint8 * 32),
        ("currentWithdrawalsRoot", ctypes.c_uint8 * 32),
        ("previousHash", ctypes.c_uint8 * 32)
    ]



# Define the Account struct
class Account(EVMWordStruct):
    _fields_ = [
        ("balance", ctypes.c_uint8 * 32),
        ("address", ctypes.c_uint8 * 32),
        ("codeSize", ctypes.c_uint32),
        ("code", ctypes.POINTER(ctypes.c_uint8)),
        ("nonce", ctypes.c_uint8 * 32),
        ("storage", ctypes.POINTER(ctypes.c_uint8)),
        ("storageSize", ctypes.c_uint32)
    ]


# Define the Transaction struct
class Transaction(EVMWordStruct):
    _fields_ = [
        ("data", ctypes.POINTER(ctypes.c_uint8)),
        ("dataSize", ctypes.c_uint32),
        ("gasLimit", ctypes.c_uint8 * 32),
        ("gasPrice", ctypes.c_uint8 * 32),
        ("nonce", ctypes.c_uint8 * 32),
        ("secretKey", ctypes.c_uint8 * 32),
        ("sender", ctypes.c_uint8 * 32),
        ("to", ctypes.c_uint8 * 32),
        ("value", ctypes.c_uint8 * 32)
    ]


# Define the PreState struct
class PreState(ctypes.Structure):
    _fields_ = [
        ("env", Env),
        ("preAccounts", ctypes.POINTER(Account)),
        ("preAccountsSize", ctypes.c_uint32),
        ("transaction", Transaction)
    ]

    def __deepcopy__(self, memo):
        if id(self) in memo:
            return memo[id(self)]

        # Create a new instance of the same type
        copied_instance = type(self)()


        setattr(copied_instance, "env", copy.deepcopy(self.env, memo))
        setattr(copied_instance, "preAccountsSize", self.preAccountsSize)
        setattr(copied_instance, "transaction", copy.deepcopy(self.transaction, memo))

        accounts = []
        for i in range(self.preAccountsSize):
            account = copy.deepcopy(self.preAccounts[i], memo)
            accounts.append(account)

        setattr(copied_instance, "preAccounts", (Account * len(accounts))(*accounts))

        # Store the copied instance in memo
        memo[id(self)] = copied_instance
        return copied_instance

def load_prestate_from_json(config):
    """Create a PreState object from a pre state JSON, assuming the JSON has been
    flattened, ie., it contains only one transaction per file."""
    env = Env(
        currentBaseFee=hex_to_evm_word_bytes(config["env"]["currentBaseFee"]),
        currentBeaconRoot=hex_to_evm_word_bytes(config["env"]["currentBeaconRoot"]),
        currentCoinbase=hex_to_evm_word_bytes(config["env"]["currentCoinbase"], False),
        currentDifficulty=hex_to_evm_word_bytes(config["env"]["currentDifficulty"]),
        currentGasLimit=hex_to_evm_word_bytes(config["env"]["currentGasLimit"]),
        currentNumber=hex_to_evm_word_bytes(config["env"]["currentNumber"]),
        currentRandom=hex_to_evm_word_bytes(config["env"]["currentRandom"]),
        currentTimestamp=hex_to_evm_word_bytes(config["env"]["currentTimestamp"]),
        currentWithdrawalsRoot=hex_to_evm_word_bytes(config["env"]["currentWithdrawalsRoot"]),
        previousHash=hex_to_evm_word_bytes(config["env"]["previousHash"])
    )

    # print("py gas limit", bytes(hex_to_evm_word_bytes(config["env"]["currentGasLimit"])))

    accounts = []
    for address, account in config["pre"].items():
        code=hex_to_bytes(account["code"])
        code_size = len(code or [])

        storage_bytes = b""
        storage_size = 0
        for key, value in account["storage"].items():
            storage_bytes += bytes(hex_to_evm_word_bytes(key))
            storage_bytes += bytes(hex_to_evm_word_bytes(value))
            storage_size += 1
        storage_bytes = (ctypes.c_uint8 * len(storage_bytes))(*storage_bytes) if storage_size > 0 else (ctypes.c_uint8 * 0)()

        accounts.append(
            Account(
                balance=hex_to_evm_word_bytes(account["balance"]),
                address=hex_to_evm_word_bytes(address),
                codeSize= code_size,
                code=code,
                nonce=hex_to_evm_word_bytes(account["nonce"]),
                storage=storage_bytes,
                storageSize=storage_size,))

    accounts = (Account * len(accounts))(*accounts)

    # Populate Transaction struct, assuming each json contains only one transaction
    tx_data = hex_to_bytes(config["transaction"]["data"][0])
    gas_limit = hex_to_evm_word_bytes(config["transaction"]["gasLimit"][0])
    gas_price = hex_to_evm_word_bytes(config["transaction"]["gasPrice"][0])
    value = hex_to_evm_word_bytes(config["transaction"]["value"][0])

    tx_data_size = len(tx_data or [])
    sender = hex_to_evm_word_bytes(config["transaction"]["sender"])
    to = hex_to_evm_word_bytes(config["transaction"]["to"])
    nonce = hex_to_evm_word_bytes(config["transaction"]["nonce"])
    secret_key = hex_to_evm_word_bytes(config["transaction"]["secretKey"])

    transaction = Transaction(
        data=tx_data,
        dataSize=tx_data_size,
        gasLimit=gas_limit,
        gasPrice=gas_price,
        nonce=nonce,
        secretKey=secret_key,
        sender=sender,
        to=to,
        value=value,
    )

    # Create PreState object
    prestate = PreState(
        env=env,
        preAccounts=accounts,
        preAccountsSize=len(accounts),
        transaction=transaction
    )

    return prestate
