from erever.utils import compute_contract_address


def test() -> None:
    addr = compute_contract_address(0xCAFE, 0)
    assert addr == 0x2FB4BEC86ABEB9724C036C544313F58A535F1AF4
