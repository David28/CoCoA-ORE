from ore_wrapper import *
import random

def test_ore():
    nbits = 32
    block_len = 8

    n1 = random.randint(0, 2**nbits - 1)
    n2 = random.randint(0, 2**nbits - 1)

    if n1 < n2:
        cmp = -1
    elif n1 == n2:
        cmp = 0
    else:
        cmp = 1

    params = ore_blk_params()
    init_ore_blk_params(pointer(params), nbits, block_len)

    sk = ore_blk_secret_key()
    ore_blk_setup(pointer(sk), pointer(params))

    ctxt1 = ore_blk_ciphertext()
    init_ore_blk_ciphertext(pointer(ctxt1), pointer(params))

    ctxt2 = ore_blk_ciphertext()
    init_ore_blk_ciphertext(pointer(ctxt2), pointer(params))

    ore_blk_encrypt_ui(pointer(ctxt1), pointer(sk), n1)
    ore_blk_encrypt_ui(pointer(ctxt2), pointer(sk), n2)

    res = c_int32()
    ore_blk_compare(pointer(res), pointer(ctxt1), pointer(ctxt2))
    assert res.value == cmp

    clear_ore_blk_ciphertext(pointer(ctxt1))
    clear_ore_blk_ciphertext(pointer(ctxt2)) 

N_TESTS = 1000
for i in range(N_TESTS):
    test_ore()
print("All tests passed")