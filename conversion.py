import ctypes
from binascii import hexlify, unhexlify
from typing import Optional
import copy

def to_ctype_byte_array(byte_array, size: Optional[int] = None, padLeft=True):
    array_size = len(byte_array)
    if size is not None:
        if array_size > size:
            raise ValueError(f"Byte array size {array_size} exceeds 32 bytes")
        if array_size < size:
            if padLeft:
                byte_array = b"\x00" * (size - array_size) + byte_array
            else:
                byte_array = byte_array + b"\x00" * (size - array_size)
    return (ctypes.c_uint8 * len(byte_array))(*byte_array)

def hex_to_ctype_bytes_with_optional_size(hex_str, size: Optional[int]=32, padLeft=True):
    try:
        hex_str = hex_str[2:] if hex_str.lower().startswith("0x") else hex_str
        if len(hex_str) % 2 != 0:
            hex_str = '0' + hex_str
        raw_bytes = unhexlify(hex_str)
        if len(raw_bytes) < 1 and size is None:
            return (ctypes.c_uint8 * 0)()
        return to_ctype_byte_array(raw_bytes, size, padLeft)
    except Exception as e:
        print(f"Error converting hex to byte array: {e}\n{hex_str}")
        raise(e)

def hex_to_evm_word_bytes(hex_str, padLeft=True):
    return hex_to_ctype_bytes_with_optional_size(hex_str, 32, padLeft)

def hex_to_bytes(hex_str):
    return hex_to_ctype_bytes_with_optional_size(hex_str, None)


class EVMWordStruct(ctypes.Structure):
    def __deepcopy__(self, memo):
        if id(self) in memo:
            return memo[id(self)]

        # Create a new instance of the same type
        copied_instance = type(self)()

        # Copy each field value using getattr and deepcopy
        for field in self._fields_:
            field_name = field[0]
            field_type = field[1]
            field_value = getattr(self, field_name)
            if isinstance(field_value, ctypes.Array):
                setattr(copied_instance, field_name, copy.deepcopy(field_value, memo))
            else:
                setattr(copied_instance, field_name, field_value)

        # Store the copied instance in memo
        memo[id(self)] = copied_instance
        return copied_instance



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


def replace_pre_accounts(prestate: PreState, json_accounts: dict):
    accounts = {}
    for i in range(prestate.preAccountsSize):
        account = prestate.preAccounts[i]
        accounts["0x" + hexlify(bytes(account.address)[12:]).decode().upper()] =  account

    for address, account in json_accounts.items():
        # update or set nonce, balance, storage
        evmAccount = accounts.get(address)

        code = account.get("code", "")
        code=hex_to_bytes(code)
        code_size = len(code or [])

        storage_bytes = b""
        storage_size = 0
        for key, value in account["storage"].items():
            storage_bytes += bytes(hex_to_evm_word_bytes(key))
            storage_bytes += bytes(hex_to_evm_word_bytes(value))
            storage_size += 1
        storage_bytes = (ctypes.c_uint8 * len(storage_bytes))(*storage_bytes) if storage_size > 0 else (ctypes.c_uint8 * 0)()

        nonce = hex_to_evm_word_bytes(f'{account.get("nonce", 0):0x}') # is a number
        balance = hex_to_evm_word_bytes(account["balance"])

        if evmAccount:
            evmAccount.nonce = nonce
            evmAccount.balance = balance
            evmAccount.storage = storage_bytes
            evmAccount.storageSize = storage_size
            # code does not exist in the post state, so we don't override it
        else:
            accounts[address] = Account(
                balance=hex_to_evm_word_bytes(account["balance"]),
                address=hex_to_evm_word_bytes(address),
                codeSize= code_size,
                code=code,
                nonce=nonce,
                storage=storage_bytes,
                storageSize=storage_size,)


    accounts = list(accounts.values())
    prestate.preAccounts = (Account * len(accounts))(*accounts)
    prestate.preAccountsSize = len(accounts)
