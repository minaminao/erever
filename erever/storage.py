
class Storage:
    def __init__(self):
        self.storage = {}

    def load(self, key):
        return self.storage.get(key, 0)

    def store(self, key, value):
        self.storage[key] = value
