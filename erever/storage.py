from .utils import UINT256_MAX


class Storage:
    storage: dict[int, int]

    def __init__(self) -> None:
        self.storage = {}

    def load(self, key: int) -> int:
        return self.storage.get(key, 0)

    def store(self, key: int, value: int) -> None:
        assert 0 <= value <= UINT256_MAX
        self.storage[key] = value

    def has(self, key: int) -> bool:
        return key in self.storage
