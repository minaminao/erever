from Crypto.Util.number import bytes_to_long
from web3 import HTTPProvider, Web3
from web3.types import TxData

from .storage import Storage
from .utils import int_to_check_sum_address

AddressInt = int


class State:
    w3: Web3 | None
    balances: dict[AddressInt, int]
    codes: dict[AddressInt, bytes]
    storages: dict[AddressInt, Storage]
    block_number: int

    def __init__(self, block_number, rpc_url: str | None = None):
        self.w3 = Web3(HTTPProvider(rpc_url)) if rpc_url else None
        self.block_number = block_number
        self.storages = {}
        self.codes = {}
        self.balances = {}

    def get_balance(self, address: AddressInt) -> int:
        if address in self.balances:
            return self.balances[address]
        elif self.w3:
            self.balances[address] = self.w3.eth.get_balance(int_to_check_sum_address(address), self.block_number)
            return self.balances[address]
        else:
            return 0

    def set_balance(self, address: AddressInt, balance: int) -> None:
        self.balances[address] = balance

    def get_code(self, address: AddressInt) -> bytes:
        if address in self.codes:
            return self.codes[address]
        elif self.w3:
            self.codes[address] = bytes(self.w3.eth.get_code(int_to_check_sum_address(address), self.block_number))
            return self.codes[address]
        else:
            return b""

    def set_code(self, address: AddressInt, code: bytes) -> None:
        self.codes[address] = code

    def get_storage_at(self, address: AddressInt, slot: int) -> int:
        if address not in self.storages:
            self.storages[address] = Storage()
        if self.storages[address].has(slot):
            return self.storages[address].load(slot)
        elif self.w3:
            self.storages[address].store(
                slot,
                bytes_to_long(self.w3.eth.get_storage_at(int_to_check_sum_address(address), slot, self.block_number)),
            )
            return self.storages[address].load(slot)
        else:
            return 0

    def set_storage_at(self, address: AddressInt, slot: int, value: int) -> None:
        if address not in self.storages:
            self.storages[address] = Storage()
        self.storages[address].store(slot, value)


class Context:
    DEFAULT_ADDRESS = 0xADD2E55
    DEFAULT_BALANCE = 0
    DEFAULT_ORIGIN = 0
    DEFAULT_CALLER = 0
    DEFAULT_CALLVALUE = 0
    DEFAULT_CALLDATA = b""
    DEFAULT_CALLDATA_HEX = ""
    DEFAULT_GASPRICE = 0
    DEFAULT_COINBASE = 0
    DEFAULT_TIMESTAMP = 0
    DEFAULT_NUMBER = 0
    DEFAULT_DIFFICULTY = 0
    DEFAULT_GASLIMIT = 0
    DEFAULT_CHAINID = 1
    DEFAULT_SELFBALANCE = 0
    DEFAULT_BASEFEE = 0
    DEFAULT_GAS = 0

    state: State
    bytecode: bytes
    address: int
    balance: int
    origin: int
    caller: int
    callvalue: int
    calldata: bytes
    calldata_hex: str
    gasprice: int
    coinbase: int
    timestamp: int
    number: int
    difficulty: int
    gaslimit: int
    chainid: int
    selfbalance: int
    basefee: int
    gas: int

    @staticmethod
    def from_arg_params_with_bytecode(args, bytecode: str) -> "Context":
        self = Context()
        self.bytecode = Context.__hex_to_bytes(bytecode)

        self.address = args.address
        self.balance = args.balance
        self.origin = args.origin
        self.caller = args.caller
        self.callvalue = args.callvalue
        self.calldata = Context.__hex_to_bytes(args.calldata)
        self.gasprice = args.gasprice
        self.coinbase = args.coinbase
        self.timestamp = args.timestamp
        self.number = args.number
        self.difficulty = args.difficulty
        self.gaslimit = args.gaslimit
        self.chainid = args.chainid
        self.selfbalance = args.selfbalance
        self.basefee = args.basefee
        self.gas = args.gas

        self.state = State(self.number)
        return self

    @staticmethod
    def from_dict(d: dict[str, int]) -> "Context":
        self = Context()
        self.bytecode = Context.__hex_to_bytes(d["bytecode"])

        self.address = d.get("address", Context.DEFAULT_ADDRESS)
        self.balance = d.get("balance", Context.DEFAULT_BALANCE)
        self.origin = d.get("origin", Context.DEFAULT_ORIGIN)
        self.caller = d.get("caller", Context.DEFAULT_CALLER)
        self.callvalue = d.get("callvalue", Context.DEFAULT_CALLVALUE)
        self.calldata = Context.__hex_to_bytes(d.get("calldata", Context.DEFAULT_CALLDATA_HEX))
        self.gasprice = d.get("gasprice", Context.DEFAULT_GASPRICE)
        self.coinbase = d.get("coinbase", Context.DEFAULT_COINBASE)
        self.timestamp = d.get("timestamp", Context.DEFAULT_TIMESTAMP)
        self.number = d.get("number", Context.DEFAULT_NUMBER)
        self.difficulty = d.get("difficulty", Context.DEFAULT_DIFFICULTY)
        self.gaslimit = d.get("gaslimit", Context.DEFAULT_GASLIMIT)
        self.chainid = d.get("chainid", Context.DEFAULT_CHAINID)
        self.selfbalance = d.get("selfbalance", Context.DEFAULT_SELFBALANCE)
        self.basefee = d.get("basefee", Context.DEFAULT_BASEFEE)
        self.gas = d.get("gas", Context.DEFAULT_GAS)

        self.state = State(self.number)
        return self

    @staticmethod
    def from_tx_hash(args) -> "Context":
        assert args.rpc_url, "RPC URL must be specified"

        w3 = Web3(HTTPProvider(args.rpc_url))
        tx: TxData = w3.eth.get_transaction(args.tx)

        self = Context()
        self.state = State(tx["blockNumber"], args.rpc_url)

        # Contract Creation
        if "to" not in tx or tx["to"] is None:
            self.bytecode = bytes(tx["input"])
            self.calldata = b""
        else:
            code = w3.eth.get_code(tx["to"], tx["blockNumber"])
            # Contract
            if len(code) > 0:
                self.bytecode = bytes(code)
                self.calldata = bytes(tx["input"])
            # EOA
            else:
                self.bytecode = bytes(tx["input"])
                self.calldata = b""

        self.address = int(tx["to"], 16)
        self.balance = args.balance
        self.origin = int(tx["from"], 16)
        self.caller = int(tx["from"], 16)
        self.callvalue = tx["value"]
        self.gasprice = tx["gasPrice"]
        self.coinbase = args.coinbase
        self.timestamp = args.timestamp
        self.number = tx["blockNumber"]
        self.difficulty = args.difficulty
        self.gaslimit = tx["gas"]
        self.chainid = tx["chainId"]
        self.selfbalance = args.selfbalance
        self.basefee = args.basefee
        self.gas = tx["gas"]
        # self.blockchash

        return self

    @staticmethod
    def from_contract_address(args) -> "Context":
        self = Context()
        assert args.rpc_url, "RPC URL must be specified"

        w3 = Web3(HTTPProvider(args.rpc_url))
        code = w3.eth.get_code(args.contract_address, args.number)
        balance = w3.eth.get_balance(args.contract_address, args.number)

        self.bytecode = bytes(code)
        assert args.address == Context.DEFAULT_ADDRESS  # TODO: priority
        self.address = Context.__hex_to_int(args.contract_address)
        assert args.balance == Context.DEFAULT_BALANCE
        self.balance = balance

        self.origin = args.origin
        self.caller = args.caller
        self.callvalue = args.callvalue
        self.calldata = Context.__hex_to_bytes(args.calldata)
        self.gasprice = args.gasprice
        self.coinbase = args.coinbase
        self.timestamp = args.timestamp
        self.number = args.number
        self.difficulty = args.difficulty
        self.gaslimit = args.gas
        self.chainid = args.chainid
        self.selfbalance = args.selfbalance
        self.basefee = args.basefee
        self.gas = args.gas
        # self.blockchash

        self.state = State(self.number, args.rpc_url)

        return self

    @staticmethod
    def __hex_to_bytes(x: str | int) -> bytes:
        if type(x) is int:
            h = hex(x)
        elif type(x) is str:
            h = x
        h = h.replace(" ", "").replace("\n", "")
        if h.startswith("0x"):
            h = h[2:]
        return bytes.fromhex(h)

    @staticmethod
    def __hex_to_int(h: str) -> int:
        if h.startswith("0x"):
            return int(h, 16)
        else:
            return int(h)
