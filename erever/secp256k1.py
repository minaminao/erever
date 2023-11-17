# secp256k1

# 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# y^2 = x^3 + 7
a = 0
b = 7


class Fp:
    def __init__(self, x: int) -> None:
        self.x = x % p

    def __add__(self, other: "Fp") -> "Fp":
        return Fp((self.x + other.x) % p)

    def __sub__(self, other: "Fp") -> "Fp":
        return Fp((self.x - other.x) % p)

    def __mul__(self, other: "Fp") -> "Fp":
        return Fp((self.x * other.x) % p)

    def __pow__(self, exponent: int) -> "Fp":
        return Fp(pow(self.x, exponent, p))

    def __truediv__(self, other: "Fp") -> "Fp":
        return self * other ** (p - 2)

    def __neg__(self) -> "Fp":
        return Fp(-self.x)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Fp):
            return False
        return self.x == other.x

    def __str__(self) -> str:
        return str(self.x)


class ECPoint:
    def __init__(self, x: Fp, y: Fp) -> None:
        self.x = x
        self.y = y

    def __add__(self, other: "ECPoint") -> "ECPoint":
        if self.is_zero():
            return other
        elif other.is_zero():
            return self
        elif self == other:
            return self._double()
        elif self == -other:
            return ECPoint(Fp(0), Fp(0))
        else:
            return self._add(other)

    def __mul__(self, other: int) -> "ECPoint":
        return self._mul(other)

    def __rmul__(self, other: int) -> "ECPoint":
        return self * other

    def _add(self, other: "ECPoint") -> "ECPoint":
        s = (other.y - self.y) / (other.x - self.x)
        x = s**2 - self.x - other.x
        y = s * (self.x - x) - self.y
        return ECPoint(x, y)

    def _double(self) -> "ECPoint":
        s = (Fp(3) * self.x**2 + Fp(a)) / (Fp(2) * self.y)
        x = s**2 - Fp(2) * self.x
        y = s * (self.x - x) - self.y
        return ECPoint(x, y)

    def _mul(self, other: int) -> "ECPoint":
        if other == 0:
            return ECPoint(Fp(0), Fp(0))
        elif other == 1:
            return self
        elif other % 2 == 0:
            return (self + self) * (other // 2)
        else:
            return self + (self + self) * ((other - 1) // 2)

    def is_zero(self) -> bool:
        return self.x == Fp(0) and self.y == Fp(0)

    def __neg__(self) -> "ECPoint":
        return ECPoint(self.x, -self.y)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ECPoint):
            return False
        return self.x == other.x and self.y == other.y

    def __str__(self) -> str:
        return f"({self.x.x}, {self.y.x})"


gx = Fp(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798)
gy = Fp(0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
G = ECPoint(gx, gy)
