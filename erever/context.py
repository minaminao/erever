from web3 import HTTPProvider, Web3


class Context:
    DEFAULT_ADDRESS = 0xadd2e55
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

    bytecode: bytes

    def from_arg_params_with_bytecode(args, bytecode):
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
        return self

    def from_dict(d: dict):
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
        return self
    
    def from_tx_hash(args):
        self = Context()
        assert args.rpc_url, "RPC URL must be specified"

        w3 = Web3(HTTPProvider(args.rpc_url))
        tx = w3.eth.get_transaction(args.tx)

        # Contract Creation
        if "to" not in tx or tx.to is None:
            self.bytecode = Context.__hex_to_bytes(tx.input)
            self.calldata = b""
        else:
            code = w3.eth.get_code(tx.to)
            # Contract
            if len(code) > 0:
                self.bytecode = bytes(code)
                self.calldata = Context.__hex_to_bytes(tx.input)
            # EOA
            else:
                self.bytecode = Context.__hex_to_bytes(tx.input)
                self.calldata = b""

        self.address = args.address
        self.balance = args.balance
        self.origin = args.origin
        self.caller = args.caller
        self.callvalue = tx.value
        self.gasprice = tx.gasPrice
        self.coinbase = args.coinbase
        self.timestamp = args.timestamp
        self.number = tx.blockNumber
        self.difficulty = args.difficulty
        self.gaslimit = tx.gas
        self.chainid = int(tx.chainId, 16)
        self.selfbalance = args.selfbalance
        self.basefee = args.basefee
        self.gas = tx.gas
        # self.blockchash

        return self

    def from_contract_address(args):
        self = Context()
        assert args.rpc_url, "RPC URL must be specified"

        w3 = Web3(HTTPProvider(args.rpc_url))
        code = w3.eth.get_code(args.contract_address)
        balance = w3.eth.get_balance(args.contract_address)

        self.bytecode = bytes(code)
        assert args.address == Context.DEFAULT_ADDRESS # TODO: priority
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

        return self


    def __hex_to_bytes(h: str | int):
        if type(h) is int:
            h = hex(h)
        h = h.replace(" ", "").replace("\n", "")
        if h.startswith("0x"):
            h = h[2:]
        return bytes.fromhex(h)

    def __hex_to_int(h: str):
        if h.startswith("0x"):
            return int(h, 16)
        else:
            return int(h)

