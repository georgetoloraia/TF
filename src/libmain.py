from typing import List, Dict
from hashlib import sha256


class COutPoint:
    def __init__(self):
        self.hash = bytes()
        self.n = 0

    def set_null(self):
        self.hash = bytes()
        self.n = -1

    def is_null(self) -> bool:
        return self.hash == bytes() and self.n == -1


class CInPoint:
    def __init__(self):
        self.ptx = None
        self.n = 0

    def set_null(self):
        self.ptx = None
        self.n = -1

    def is_null(self) -> bool:
        return self.ptx is None and self.n == -1


class CDiskTxPos:
    def __init__(self):
        self.nFile = 0
        self.nBlockPos = 0
        self.nTxPos = 0

    def set_null(self):
        self.nFile = -1
        self.nBlockPos = 0
        self.nTxPos = 0

    def is_null(self) -> bool:
        return self.nFile == -1

    def print(self):
        if self.is_null():
            print("null")
        else:
            print(f"(nFile={self.nFile}, nBlockPos={self.nBlockPos}, nTxPos={self.nTxPos})")


class CTxIn:
    def __init__(self):
        self.prevout = COutPoint()
        self.scriptSig = bytes()

    def is_prev_in_main_chain(self) -> bool:
        return True  # Assuming CTxDB function always returns True for simplicity

    def print(self):
        print("CTxIn(", end="")
        self.prevout.print()
        if self.prevout.is_null():
            print(f", coinbase {self.scriptSig.hex()})\n")
        else:
            if len(self.scriptSig) >= 6:
                print(f", scriptSig={self.scriptSig[4]:02x}{self.scriptSig[5]:02x}")
            print(")\n")


class CTxOut:
    def __init__(self):
        self.nValue = 0
        self.nSequence = 0
        self.scriptPubKey = bytes()
        self.posNext = CDiskTxPos()

    def is_final(self) -> bool:
        return self.nSequence == 0xFFFFFFFF

    def is_mine(self) -> bool:
        return False  # Implement this according to your logic

    def get_credit(self) -> int:
        return self.nValue if self.is_mine() else 0

    def print(self):
        print(f"CTxOut(nValue={self.nValue}, nSequence={self.nSequence}, "
              f"scriptPubKey={self.scriptPubKey[4:6].hex()}, posNext=", end="")
        self.posNext.print()
        print(")\n")


class CTransaction:
    def __init__(self):
        self.vin: List[CTxIn] = []
        self.vout: List[CTxOut] = []
        self.nLockTime = 0

    def set_null(self):
        self.vin.clear()
        self.vout.clear()
        self.nLockTime = 0

    def is_null(self) -> bool:
        return len(self.vin) == 0 and len(self.vout) == 0

    def get_hash(self) -> bytes:
        return sha256(self.serialize()).digest()  # Assuming serialize function exists

    def all_prev_in_main_chain(self) -> bool:
        return all(txin.is_prev_in_main_chain() for txin in self.vin)

    def is_final(self) -> bool:
        if self.nLockTime == 0:
            return True
        if self.nLockTime < get_adjusted_time():
            return True
        return all(txout.is_final() for txout in self.vout)

    def is_coin_base(self) -> bool:
        return len(self.vin) == 1 and self.vin[0].prevout.is_null()

    def check_transaction(self) -> bool:
        if not self.vin or not self.vout:
            return False
        nValueOut = sum(txout.nValue for txout in self.vout)
        if self.is_coin_base():
            if len(self.vin[0].scriptSig) > 100:
                return False
        else:
            if any(txin.prevout.is_null() for txin in self.vin):
                return False
        return True

    def is_mine(self) -> bool:
        return any(txout.is_mine() for txout in self.vout)

    def get_debit(self) -> int:
        return sum(txin.get_debit() for txin in self.vin)

    def get_credit(self) -> int:
        return sum(txout.get_credit() for txout in self.vout)

    def get_value_out(self) -> int:
        return sum(txout.nValue for txout in self.vout)

    def get_min_fee(self, nBlockSize: int, nBytes: int) -> int:
        return 0  # Implement this according to your logic

    def get_min_fee_per_kb(self) -> int:
        return 0  # Implement this according to your logic

    def get_total_size(self) -> int:
        return len(self.serialize())  # Assuming serialize function exists

    def get_transaction_fee(self, nBlockSize: int) -> int:
        return max(self.get_debit() - self.get_credit(), 0)

    def print(self):
        print("CTransaction(", end="")
        print("vin=", end="")
        print("[")
        for txin in self.vin:
            txin.print()
        print("],")
        print("vout=", end="")
        print("[")
        for txout in self.vout:
            txout.print()
        print("],")
        print(f"nLockTime={self.nLockTime})\n")
