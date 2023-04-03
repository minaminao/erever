# erever - EVM Reversing Tools

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

### Other options
```
$ erever -h
usage: erever [-h] [-b BYTECODE] [-f FILENAME] [-c CONTRACT_ADDRESS] [--tx TX] [--rpc-url RPC_URL] [--trace] [--symbolic] [--entrypoint ENTRYPOINT]
              [--show-symbolic-stack] [-n N] [--decode-stack] [--address ADDRESS] [--balance BALANCE] [--origin ORIGIN] [--caller CALLER]
              [--callvalue CALLVALUE] [--calldata CALLDATA] [--gasprice GASPRICE] [--coinbase COINBASE] [--timestamp TIMESTAMP] [--number NUMBER]
              [--difficulty DIFFICULTY] [--gaslimit GASLIMIT] [--chainid CHAINID] [--selfbalance SELFBALANCE] [--basefee BASEFEE] [--gas GAS]

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
  -n N
  --decode-stack
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

## Writeups with erever
- [Paradigm CTF 2022: SOURCECODE](https://github.com/minaminao/ctf-blockchain/tree/main/src/ParadigmCTF2022#sourcecode)
- [DownUnderCTF 2022: EVM Vault Mechanism](https://github.com/minaminao/ctf-blockchain/tree/main/src/DownUnderCTF2022/EVMVaultMechanism)
- [EKOPARTY CTF 2022: Byte](https://github.com/minaminao/ctf-blockchain/tree/main/src/EkoPartyCTF2022)
- [EKOPARTY CTF 2022: SmartRev](https://github.com/minaminao/ctf-blockchain/tree/main/src/EkoPartyCTF2022)
