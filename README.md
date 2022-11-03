# erever - EVM Reversing Tools (WIP)

## Install
```
pip install git+https://github.com/minaminao/erever.git
```

Only supports Python >= 3.10.

## Usage
```
$ erever -h
usage: erever [-h] [-b BYTECODE] [-f FILENAME] [--tx TX] [--trace] [--symbolic] [--entrypoint ENTRYPOINT] [--show-symbolic-stack] [-n N] [--rpc-url RPC_URL] [--address ADDRESS] [--balance BALANCE]
              [--origin ORIGIN] [--caller CALLER] [--callvalue CALLVALUE] [--calldata CALLDATA] [--gasprice GASPRICE] [--coinbase COINBASE] [--timestamp TIMESTAMP] [--number NUMBER]
              [--difficulty DIFFICULTY] [--gaslimit GASLIMIT] [--chainid CHAINID] [--selfbalance SELFBALANCE] [--basefee BASEFEE] [--gas GAS]

EVM Reversing Tools

options:
  -h, --help            show this help message and exit
  -b BYTECODE, --bytecode BYTECODE
  -f FILENAME, --filename FILENAME
  --tx TX
  --trace
  --symbolic
  --entrypoint ENTRYPOINT
  --show-symbolic-stack
  -n N
  --rpc-url RPC_URL
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

## Disassemble and trace stack and memory
Source: [A quine for the SOURCECODE challenge in Paradigm CTF 2022](https://github.com/minaminao/ctf-blockchain/blob/main/src/ParadigmCTF2022/SourceCode/Quine35Bytes.huff).

```c
$ erever -b "70806011526000526070600e536023600ef3806011526000526070600e536023600ef3" --trace
0x00: PUSH17 0x806011526000526070600e536023600ef3
        stack   [0x806011526000526070600e536023600ef3]
0x12: DUP1(0x806011526000526070600e536023600ef3)
        stack   [0x806011526000526070600e536023600ef3, 0x806011526000526070600e536023600ef3]
0x13: PUSH1 0x11
        stack   [0x11, 0x806011526000526070600e536023600ef3, 0x806011526000526070600e536023600ef3]
0x15: MSTORE(offset:0x11, x:0x806011526000526070600e536023600ef3)
        stack   [0x806011526000526070600e536023600ef3]
        memory  0000000000000000000000000000000000000000000000000000000000000000
                806011526000526070600e536023600ef3000000000000000000000000000000
0x16: PUSH1 0x00
        stack   [0x00, 0x806011526000526070600e536023600ef3]
        memory  0000000000000000000000000000000000000000000000000000000000000000
                806011526000526070600e536023600ef3000000000000000000000000000000
0x18: MSTORE(offset:0x00, x:0x806011526000526070600e536023600ef3)
        stack   []
        memory  000000000000000000000000000000806011526000526070600e536023600ef3
                806011526000526070600e536023600ef3000000000000000000000000000000
0x19: PUSH1 0x70
        stack   [0x70]
        memory  000000000000000000000000000000806011526000526070600e536023600ef3
                806011526000526070600e536023600ef3000000000000000000000000000000
0x1b: PUSH1 0x0e
        stack   [0x0e, 0x70]
        memory  000000000000000000000000000000806011526000526070600e536023600ef3
                806011526000526070600e536023600ef3000000000000000000000000000000
0x1d: MSTORE8(offset:0x0e, x:0x70)
        stack   []
        memory  000000000000000000000000000070806011526000526070600e536023600ef3
                806011526000526070600e536023600ef3000000000000000000000000000000
0x1e: PUSH1 0x23
        stack   [0x23]
        memory  000000000000000000000000000070806011526000526070600e536023600ef3
                806011526000526070600e536023600ef3000000000000000000000000000000
0x20: PUSH1 0x0e
        stack   [0x0e, 0x23]
        memory  000000000000000000000000000070806011526000526070600e536023600ef3
                806011526000526070600e536023600ef3000000000000000000000000000000
0x22: RETURN(offset:0x0e, size:0x23)
        return  70806011526000526070600e536023600ef3806011526000526070600e536023600ef3
```

## Writeups with elever
- [Paradigm CTF 2022: SOURCECODE](https://github.com/minaminao/ctf-blockchain/tree/main/src/ParadigmCTF2022#sourcecode)
- [DownUnderCTF 2022: EVM Vault Mechanism](https://github.com/minaminao/ctf-blockchain/tree/main/src/DownUnderCTF2022/EVMVaultMechanism)
