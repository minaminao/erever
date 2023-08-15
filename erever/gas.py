from dataclasses import dataclass

from .types import Gas

GAS_CALL_STIPEND = 2300
GAS_CODE_WARM_COLD_DIFF = 2600 - 100


@dataclass
class MessageCallGas:
    cost: int
    stipend: int


def calculate_message_call_gas(
    value: int, gas: Gas, gas_left: Gas, memory_cost: Gas, extra_gas: Gas, call_stipend: Gas = GAS_CALL_STIPEND
) -> MessageCallGas:
    call_stipend = 0 if value == 0 else call_stipend
    if gas_left < extra_gas + memory_cost:
        return MessageCallGas(gas + extra_gas, gas + call_stipend)

    gas = min(gas, max_message_call_gas(gas_left - memory_cost - extra_gas))

    return MessageCallGas(gas + extra_gas, gas + call_stipend)


def max_message_call_gas(gas: Gas) -> Gas:
    return gas - (gas // 64)
