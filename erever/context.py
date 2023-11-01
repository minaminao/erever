import argparse

from Crypto.Util.number import bytes_to_long
from web3 import HTTPProvider, Web3
from web3.types import BlockData, TxData

from .precompiled_contracts import PRECOMPILED_CONTRACTS
from .storage import Storage
from .types import AddressInt, Gas
from .utils import UINT256_MAX, int_to_check_sum_address


class State:
    w3: Web3 | None
    balances: dict[AddressInt, int]
    codes: dict[AddressInt, bytes]
    storages: dict[AddressInt, Storage]
    original_storages: dict[AddressInt, Storage]
    address_access_set: set[AddressInt]
    block_number: int

    def __init__(self, block_number: int, rpc_url: str | None = None) -> None:
        self.w3 = Web3(HTTPProvider(rpc_url)) if rpc_url else None
        self.block_number = block_number
        self.storages = {}
        self.original_storages = {}
        self.codes = {address: b"" for address in PRECOMPILED_CONTRACTS}
        self.address_access_set = set([address for address in PRECOMPILED_CONTRACTS])
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
            code = self.codes[address]
            return code
        elif self.w3:
            code = bytes(self.w3.eth.get_code(int_to_check_sum_address(address), self.block_number))
            self.codes[address] = code
            return code
        else:
            return b""

    def set_code(self, address: AddressInt, code: bytes) -> None:
        self.codes[address] = code

    def get_storage_at(self, address: AddressInt, slot: int) -> tuple[int, Gas]:
        GAS_WARM_COLD_DIFF = 2100 - 100

        if address not in self.storages:
            self.storages[address] = Storage()
        if address not in self.original_storages:
            self.original_storages[address] = Storage()

        storage = self.storages[address]
        original_storage = self.original_storages[address]

        if not original_storage.has(slot):
            if self.w3:
                original_storage.store(
                    slot,
                    bytes_to_long(
                        self.w3.eth.get_storage_at(int_to_check_sum_address(address), slot, self.block_number)
                    ),
                )
            else:
                original_storage.store(slot, 0)

        original_value = original_storage.load(slot)
        warm = storage.has(slot)
        if not warm:
            storage.store(slot, original_value)
        current_value = storage.load(slot)

        return (current_value, 0 if warm else GAS_WARM_COLD_DIFF)

    def set_storage_at(self, address: AddressInt, slot: int, value: int) -> tuple[Gas, Gas]:
        if address not in self.storages:
            self.storages[address] = Storage()
        if address not in self.original_storages:
            self.original_storages[address] = Storage()

        storage = self.storages[address]
        original_storage = self.original_storages[address]

        if not original_storage.has(slot):
            if self.w3:
                original_storage.store(
                    slot,
                    bytes_to_long(
                        self.w3.eth.get_storage_at(int_to_check_sum_address(address), slot, self.block_number)
                    ),
                )
            else:
                original_storage.store(slot, 0)

        original_value = original_storage.load(slot)
        warm = storage.has(slot)
        if not warm:
            storage.store(slot, original_value)
        current_value = storage.load(slot)

        # https://www.evm.codes/#55?fork=shanghai
        if value == current_value:
            base_dynamic_gas = 100
        elif current_value == original_value:
            if original_value == 0:
                base_dynamic_gas = 20000
            else:
                base_dynamic_gas = 2900
        else:
            base_dynamic_gas = 100

        gas_refunds = 0
        if value != current_value:
            if current_value == original_value:
                if original_value != 0 and value == 0:
                    gas_refunds += 4800
            else:
                if original_value != 0:
                    if current_value == 0:
                        gas_refunds -= 4800
                    elif value == 0:
                        gas_refunds += 4800
                if value == original_value:
                    if original_value == 0:
                        gas_refunds += 19900
                    else:
                        if warm:
                            gas_refunds += 5000 - 2100 - 100
                        else:
                            gas_refunds += 4900
        storage.store(slot, value)

        # print(address, slot, " ", base_dynamic_gas, gas_refunds, value, current_value, original_value, warm, file=sys.stderr)

        gas = base_dynamic_gas - 100
        # gas refunds are applied at the end of the transaction
        return (gas, gas_refunds)


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
    DEFAULT_GAS = UINT256_MAX

    state: State
    bytecode: bytes
    address: int
    balance: int
    origin: int
    caller: int
    callvalue: int
    calldata: bytes
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

    static: bool
    return_data: bytes
    depth: int
    steps: int

    @staticmethod
    def from_arg_params_with_bytecode(args: argparse.Namespace, bytecode: str) -> "Context":
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

        self.state = State(self.number, args.rpc_url)
        self.static = False
        self.return_data = b""
        self.depth = 1
        self.steps = 0
        return self

    @staticmethod
    def from_dict(d: dict) -> "Context":
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

        self.state = State(self.number, d.get("rpc_url", None))
        self.static = False
        self.return_data = b""
        self.depth = 1
        self.steps = 0
        return self

    @staticmethod
    def from_tx_hash(args: argparse.Namespace) -> "Context":
        assert args.rpc_url, "RPC URL must be specified"

        w3 = Web3(HTTPProvider(args.rpc_url))
        tx: TxData = w3.eth.get_transaction(args.tx)

        self = Context()
        previous_block_number = tx["blockNumber"] - 1  # not includes tx
        current_block_number = tx["blockNumber"]  # includes tx
        self.state = State(previous_block_number, args.rpc_url)

        current_block: BlockData = w3.eth.get_block(current_block_number)

        # Contract Creation
        if "to" not in tx or tx["to"] is None:
            self.bytecode = bytes(tx["input"])
            self.calldata = b""
        else:
            to_address = int(tx["to"], 16)
            self.state.address_access_set.add(to_address)
            code = self.state.get_code(to_address)
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
        self.timestamp = current_block["timestamp"]
        self.number = current_block_number
        self.difficulty = args.difficulty
        self.gaslimit = tx["gas"]
        self.chainid = tx.get("chainId", args.chainid)
        self.selfbalance = args.selfbalance
        self.basefee = current_block.get("baseFeePerGas", args.basefee)
        self.gas = tx["gas"]
        # self.blockchash

        self.static = False
        self.return_data = b""
        self.depth = 1
        self.steps = 0
        return self

    @staticmethod
    def from_contract_address(args: argparse.Namespace) -> "Context":
        self = Context()
        assert args.rpc_url, "RPC URL must be specified"

        w3 = Web3(HTTPProvider(args.rpc_url))
        if args.number == 0:
            args.number = w3.eth.block_number
        if args.timestamp == 0:
            args.timestamp = w3.eth.get_block(args.number)["timestamp"]

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
        self.static = False
        self.return_data = b""
        self.depth = 1
        self.steps = 0
        return self

    @staticmethod
    def __hex_to_bytes(x: str | int) -> bytes:
        if isinstance(x, int):
            h = hex(x)
        elif isinstance(x, str):
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
