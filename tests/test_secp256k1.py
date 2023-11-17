from erever.secp256k1 import Fp, ECPoint, G


def test_key_pair() -> None:
    # openssl ecparam -genkey -name secp256k1 -text -noout -outform DER | xxd -p -c 1000 | sed 's/41534e31204f49443a20736563703235366b310a30740201010420/\nPrivate Key: /' | sed 's/a00706052b8104000aa144034200/\'$'\nPublic Key: /'
    private_key = 0xFAE0CE9EE78E6C3BD4AC3CEC2C18932AE1D374DBA0EF7A4D76024D1A49286C60
    public_key = ECPoint(
        Fp(0xF6A49909F37B380914450718E75D53443F3C5848DF95A2DFE684308B700859A5),
        Fp(0x5C5556D2225A89747AB2BF12808B24D7A663282CA7A32849C0D47BB9710AE979),
    )
    assert private_key * G == public_key
