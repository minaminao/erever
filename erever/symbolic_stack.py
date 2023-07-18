from .node import Node


class SymbolicStack:
    def __init__(self):
        self.var_n = 0
        self.stack: list[Node] = []

    def push(self, x: Node):
        self.stack.append(x)

    def extend(self, x: list[Node]):
        self.stack.extend(x)

    def pop(self) -> Node:
        if len(self.stack) == 0:
            ret = Node("var", f"var_{self.var_n}")
            self.var_n += 1
            return ret
        else:
            return self.stack.pop()

    def clear(self):
        self.stack = []

    def __repr__(self):
        return repr(self.stack[::-1])
    
    def to_string(self):
        return self.__repr__()
