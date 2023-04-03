# erever

erever is a CLI tool for reversing EVM bytecode.
It is specially optimized for solving CTF challenges and is intended to be used for tricky operations.
For general use, it is recommended to use other useful tools such as the debugger included in Foundry.
Currently, it is mostly for me to solve challenges and is not intended to be used by others, but if you have trouble using this tool, please open a issue!

- [Install](#install)
- [Usage](#usage)
  - [Disassemble](#disassemble)
  - [Trace stack and memory](#trace-stack-and-memory)
  - [Symbolic execution](#symbolic-execution)
  - [Other options](#other-options)
  - [Tips](#tips)
- [Writeups with erever](#writeups-with-erever)

## Install
```
pip install git+https://github.com/minaminao/erever.git
```

Only supports Python >= 3.11.

## Usage

### Disassemble
(Bytecode: [A quine for the SOURCECODE challenge in Paradigm CTF 2022](https://github.com/minaminao/ctf-blockchain/blob/main/src/ParadigmCTF2022/SourceCode/Quine35Bytes.huff))

```
$ erever -b "70806011526000526070600e536023600ef3806011526000526070600e536023600ef3"
0x00: PUSH17 0x806011526000526070600e536023600ef3
0x12: DUP1
0x13: PUSH1 0x11
0x15: MSTORE
0x16: PUSH1 0x00
0x18: MSTORE
0x19: PUSH1 0x70
0x1b: PUSH1 0x0e
0x1d: MSTORE8
0x1e: PUSH1 0x23
0x20: PUSH1 0x0e
0x22: RETURN
```

### Trace stack and memory
![](https://i.gyazo.com/217facab973e74f0b9181e74beda8fbd.png)

### Symbolic execution

```
$ erever -b 0x6080604052600436106100385760003560e01c80634b64e4921461004457806380e10aa514610066578063b15be2f51461006e57600080fd5b3661003f57005b600080fd5b34801561005057600080fd5b5061006461005f366004610300565b610083565b005b61006461018e565b34801561007a57600080fd5b5061006461022a565b6040805163bfa814b560e01b602082015282916000916001600160a01b038416910160408051601f19818403018152908290526100bf91610330565b600060405180830381855af49150503d80600081146100fa576040519150601f19603f3d011682016040523d82523d6000602084013e6100ff565b606091505b5050905080156101425760405162461bcd60e51b81526020600482015260096024820152686e6f20636f7665722160b81b60448201526064015b60405180910390fd5b60008061014d610251565b909250905043821461015e57600080fd5b604080516020810190915261022a820180825261017d9063ffffffff16565b5050505061018a81610280565b5050565b6000546001600160a01b031633146101a557600080fd5b346001146101f55760405162461bcd60e51b815260206004820152601b60248201527f49206f6e6c79206e6565642061206c6974746c65206d6f6e65792100000000006044820152606401610139565b6040513381527f2d3bd82a572c860ef85a36e8d4873a9deed3f76b9fddbf13fbe4fe8a97c4a5799060200160405180910390a1565b6000546001600160a01b031661023f57600080fd5b600080546001600160a01b0319169055565b60008060403d1461026157600080fd5b60405160406000823e63ffffffff815116925080602001519150509091565b600061028b826102dc565b9050806102c75760405162461bcd60e51b815260206004820152600a6024820152693832b936b4b9b9b4b7b760b11b6044820152606401610139565b336001600160a01b0383161461018a57600080fd5b6000813b806102ee5750600092915050565b600c8111156100645750600092915050565b60006020828403121561031257600080fd5b81356001600160a01b038116811461032957600080fd5b9392505050565b6000825160005b818110156103515760208186018101518583015201610337565b81811115610360576000828501525b50919091019291505056fea2646970667358221220f9b740c6afb3d0144cfc4fde3b00baa8b2e5d087e61ef21d572db9ba3095d36a64736f6c634300080c0033 --symbolic --max-steps 50 --show-symbolic-stack

0x000
0x000: PUSH1 0x80
   stack    [0x80]
0x002: PUSH1 0x40
   stack    [0x40, 0x80]
0x004: MSTORE(0x40, 0x80)
   stack    []
0x005: PUSH1 0x04
   stack    [0x04]
0x007: CALLDATASIZE()
   stack    [CALLDATASIZE(), 0x04]
0x008: CALLDATASIZE() < 0x04
   stack    [(CALLDATASIZE() < 0x04)]
0x009: PUSH2 0x0038
   stack    [0x38, (CALLDATASIZE() < 0x04)]
0x00c: JUMPI(0x38, CALLDATASIZE() < 0x04)
   stack    []

0x038 (<- 0x00c)
   0x00c: (CALLDATASIZE() < 0x04) == true
0x038: JUMPDEST
   stack    []
0x039: CALLDATASIZE()
   stack    [CALLDATASIZE()]
0x03a: PUSH2 0x003f
   stack    [0x3f, CALLDATASIZE()]
0x03d: JUMPI(0x3f, CALLDATASIZE())
   stack    []

0x00d (<- 0x00c)
   0x00c: (CALLDATASIZE() < 0x04) == false
0x00d: PUSH1 0x00
   stack    [0x00]
0x00f: CALLDATALOAD(0x00)
   stack    [CALLDATALOAD(0x00)]
0x010: PUSH1 0xe0
   stack    [0xe0, CALLDATALOAD(0x00)]
0x012: CALLDATALOAD(0x00) >> 0xe0
   stack    [(CALLDATALOAD(0x00) >> 0xe0)]
0x013: DUP1((CALLDATALOAD(0x00) >> 0xe0))
   stack    [(CALLDATALOAD(0x00) >> 0xe0), (CALLDATALOAD(0x00) >> 0xe0)]
0x014: PUSH4 0x4b64e492
   stack    [0x4b64e492, (CALLDATALOAD(0x00) >> 0xe0), (CALLDATALOAD(0x00) >> 0xe0)]
0x019: 0x4b64e492 == (CALLDATALOAD(0x00) >> 0xe0)
   stack    [(0x4b64e492 == (CALLDATALOAD(0x00) >> 0xe0)), (CALLDATALOAD(0x00) >> 0xe0)]
0x01a: PUSH2 0x0044
   stack    [0x44, (0x4b64e492 == (CALLDATALOAD(0x00) >> 0xe0)), (CALLDATALOAD(0x00) >> 0xe0)]
0x01d: JUMPI(0x44, 0x4b64e492 == (CALLDATALOAD(0x00) >> 0xe0))
   stack    [(CALLDATALOAD(0x00) >> 0xe0)]
```

### Other options
```
$ erever -h
usage: erever [-h] [-b BYTECODE] [-f FILENAME] [-c CONTRACT_ADDRESS] [--tx TX] [--rpc-url RPC_URL] [--trace] [--symbolic]
              [--entrypoint ENTRYPOINT] [--show-symbolic-stack] [--max-steps MAX_STEPS] [--decode-stack] [--mermaid] [--hide-pc]
              [--hide-opcodes-with-no-stack-output] [--address ADDRESS] [--balance BALANCE] [--origin ORIGIN] [--caller CALLER]
              [--callvalue CALLVALUE] [--calldata CALLDATA] [--gasprice GASPRICE] [--coinbase COINBASE] [--timestamp TIMESTAMP]
              [--number NUMBER] [--difficulty DIFFICULTY] [--gaslimit GASLIMIT] [--chainid CHAINID] [--selfbalance SELFBALANCE]
              [--basefee BASEFEE] [--gas GAS]

EVM Reversing Tools

options:
  -h, --help            show this help message and exit
  -b BYTECODE, --bytecode BYTECODE
  -f FILENAME, --filename FILENAME
  -c CONTRACT_ADDRESS, --contract-address CONTRACT_ADDRESS
  --tx TX
  --rpc-url RPC_URL
  --trace
  --symbolic
  --entrypoint ENTRYPOINT
  --show-symbolic-stack
  --max-steps MAX_STEPS
  --decode-stack
  --mermaid
  --hide-pc
  --hide-opcodes-with-no-stack-output
  --address ADDRESS
  --balance BALANCE
  --origin ORIGIN
  --caller CALLER
  --callvalue CALLVALUE
  --calldata CALLDATA
  --gasprice GASPRICE
  --coinbase COINBASE
  --timestamp TIMESTAMP
  --number NUMBER
  --difficulty DIFFICULTY
  --gaslimit GASLIMIT
  --chainid CHAINID
  --selfbalance SELFBALANCE
  --basefee BASEFEE
  --gas GAS
```

### Tips
- It is useful in combination with commands such as `less -R` and `less -R -S`.

## Writeups with erever
- [Paradigm CTF 2022: SOURCECODE](https://github.com/minaminao/ctf-blockchain/tree/main/src/ParadigmCTF2022#sourcecode)
- [DownUnderCTF 2022: EVM Vault Mechanism](https://github.com/minaminao/ctf-blockchain/tree/main/src/DownUnderCTF2022/EVMVaultMechanism)
- [EKOPARTY CTF 2022: Byte](https://github.com/minaminao/ctf-blockchain/tree/main/src/EkoPartyCTF2022)
- [EKOPARTY CTF 2022: SmartRev](https://github.com/minaminao/ctf-blockchain/tree/main/src/EkoPartyCTF2022)
- [Numen Cyber CTF 2023: LittleMoney](https://github.com/minaminao/ctf-blockchain/tree/main/src/NumenCTF)
- [Numen Cyber CTF 2023: HEXP](https://github.com/minaminao/ctf-blockchain/tree/main/src/NumenCTF)
