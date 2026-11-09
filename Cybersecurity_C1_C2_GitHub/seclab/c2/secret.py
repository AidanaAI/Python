from __future__ import annotations

from hmac import compare_digest

class Secret:
    __slots__ = ("__value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("Secret requires a string")
        self.__value = value

    def reveal(self) -> str:
        return self.__value

    def __repr__(self) -> str:
        return "Secret('********')"

    def __str__(self) -> str:
        return self.__repr__()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secret):
            return NotImplemented
        return compare_digest(self.__value, other.__value)

    def __hash__(self) -> int:

        return hash(self.__value)
