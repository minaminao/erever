from .node import Node


class SymbolicStack:
    var_n: int
    stack: list[Node]

    def __init__(self) -> None:
        self.var_n = 0
        self.stack = []

    def push(self, x: Node) -> None:
        self.stack.append(x)

    def extend(self, x: list[Node]) -> None:
        self.stack.extend(x)

    def pop(self) -> Node:
        if len(self.stack) == 0:
            ret = Node("var", f"var_{self.var_n}")
            self.var_n += 1
            return ret
        else:
            return self.stack.pop()

    def __len__(self) -> int:
        return len(self.stack)

    def clear(self) -> None:
        self.stack = []

    def __repr__(self) -> str:
        return repr(self.stack[::-1])

    def to_string(self) -> str:
        return self.__repr__()
