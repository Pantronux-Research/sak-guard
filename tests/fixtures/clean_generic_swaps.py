"""Non-financial swaps must not be treated as Solana trades."""


def swap(left, right):
    return right, left


def re_route(message):
    return message


pair = swap(1, 2)
message = re_route("hello")
