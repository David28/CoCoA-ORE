from ore_wrapper import *
import random
N_TESTS = 1000
import random
sks = []
#print sizeof(ore_params)
def test_ore(msg1, msg2):
    # setup
    sk, params = getInitiatedParams()
    ore_val1 = ore_val(msg1, sk, params)
    ore_val2 = ore_val(msg2, sk, params)
    
    # assertions
    assert (ore_val1 < ore_val2) == (msg1 < msg2)
    assert (ore_val1 <= ore_val2) == (msg1 <= msg2)
    assert (ore_val1 == ore_val2) == (msg1 == msg2)
    assert (ore_val1 != ore_val2) == (msg1 != msg2)
    assert (ore_val1 > ore_val2) == (msg1 > msg2)
    assert (ore_val1 >= ore_val2) == (msg1 >= msg2)
    
    #cleanup
    ore_val1.cleanup()
    ore_val2.cleanup()


test_ore(1,3)
for i in range(N_TESTS):
    msg1 = random.randint(0, 2**32 - 1)
    msg2 = random.randint(0, 2**32 - 1)
    
    #throws assertion error
    test_ore(msg1, msg2)
    #print("Test {} passed".format(i))


print("All simple tests passed")

#test sorting
ARR_LEN = 100
nbits = 32
arr = [random.randint(0, 2**nbits - 1) for i in range(ARR_LEN)]
sk, params = getInitiatedParams()
enc_arr = [ore_val(msg, sk, params) for msg in arr]
zipped = list(zip(enc_arr,arr))
zipped.sort()
enc_arr, arr = zip(*zipped)
for i in range(ARR_LEN - 1):
    assert arr[i] <= arr[i+1]
print("All sorting tests passed")