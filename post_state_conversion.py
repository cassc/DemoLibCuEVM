import ctypes

# Define the Post Env struct
class Event(ctypes.Structure):
    _fields_ = [
        ("stack", ctypes.c_uint8 * 64),
        ("res", ctypes.c_uint8 * 32),
        ("pc", ctypes.c_uint32),
        ("op", ctypes.c_uint8)
    ]
    _align_ = 16

class Branch(ctypes.Structure):
    _fields_ = [
        ("pcSrc", ctypes.c_uint32),
        ("pcDst", ctypes.c_uint32),
        ("pcMissed", ctypes.c_uint32),
        ("distance", ctypes.c_uint8 * 32)
    ]
    _align_ = 16

class Call(ctypes.Structure):
    _fields_ = [
        ("sender", ctypes.c_uint8 * 32),
        ("receiver", ctypes.c_uint8 * 32),
        ("value", ctypes.c_uint8 * 32),
        ("pc", ctypes.c_uint32),
        ("op", ctypes.c_uint8),
        ("success", ctypes.c_bool)
    ]
    _align_ = 16

class Account(ctypes.Structure):
    _fields_ = [
        ("balance", ctypes.c_uint8 * 32),
        ("address", ctypes.c_uint8 * 32),
        ("nonce", ctypes.c_uint8 * 32),
        ("storage", ctypes.POINTER(ctypes.c_uint8)),  # pointer to uint8_t storage
        ("storageSize", ctypes.c_uint32)  # number of 64-byte entries
    ]
    _align_ = 16

class Trace(ctypes.Structure):
    _fields_ = [
        ("events", ctypes.POINTER(Event)),
        ("eventsSize", ctypes.c_uint32),
        ("branches", ctypes.POINTER(Branch)),
        ("branchesSize", ctypes.c_uint32),
        ("calls", ctypes.POINTER(Call)),
        ("callsSize", ctypes.c_uint32)
    ]
    _align_ = 16

class PostState(ctypes.Structure):
    _fields_ = [
        ("postAccounts", ctypes.POINTER(Account)),
        ("postAccountsSize", ctypes.c_uint32),
        ("trace", Trace)
    ]
    _align_ = 16
