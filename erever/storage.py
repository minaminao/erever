class Storage:
    storage: dict[int, int]

    def __init__(self) -> None:
        self.storage = {}

    def load(self, key: int) -> int:
        return self.storage.get(key, 0)

    def store(self, key: int, value: int) -> None:
        self.storage[key] = value
