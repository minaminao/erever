import base58
import cbor2
import requests


def inspect_cbor(bytecode: bytes) -> None:
    if len(bytecode) < 2:
        return
    length = int.from_bytes(bytecode[-2:], "big")
    if length >= len(bytecode):
        print("CBOR: Not found")
        return
    print(f"CBOR: length = {length}")

    cbor_data = bytecode[-length - 2 : -2]
    try:
        cbor_obj = cbor2.loads(cbor_data)
    except Exception:
        print("CBOR: Failed to parse")
        return
    assert isinstance(cbor_obj, dict)
    for k, v in cbor_obj.items():
        assert isinstance(k, str)
        assert isinstance(v, bytes)
        if k == "ipfs":
            ipfs_hash = base58.b58encode(v)
            ipfs_url = f"https://ipfs.io/ipfs/{ipfs_hash.decode()}"
            print(f"CBOR: {k} = {ipfs_url}")
            response = requests.get(ipfs_url)
            if response.status_code == 200:
                response_data = response.text.encode()
                if len(response_data) > 0x100:
                    response_data = response_data[:0x100] + b"..."
                print("CBOR: ipfs content =", response_data)
        elif k == "solc":
            assert len(v) == 3
            x, y, z = v
            print(f"CBOR: {k} = {x}.{y}.{z}")
        else:
            print(f"CBOR: {k} = {v.hex()}")
