import json

def pow_mod(x, y, z):
    "Calculate (x ** y) % z efficiently."
    number = 1
    while y:
        if y & 1:
            number = number * x % z
        y >>= 1
        x = x * x % z
    return number

p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f

def uncompress(compressed_key):
    y_parity = int(compressed_key[:2]) - 2
    x = int(compressed_key[2:], 16)
    a = (pow_mod(x, 3, p) + 7) % p
    y = pow_mod(a, (p+1)//4, p)
    if y % 2 != y_parity:
        y = -y % p
    #uncompressed_key = '04{:x}{:x}'.format(x, y)
    uncompressed_key = '04{0:0{1}x}{2:0{3}x}'.format(x,64,y,64)
    return uncompressed_key


#####################################################################################
## compressed_key = '02c0ded2bc1f1305fb0faac5e6c03ee3a1924234985427b6167ca569d13df435cf'
#uncompressed_key = uncompress(compressed_key)

## should get 0414fc03b8df87cd7b872996810db8458d61da8448e531569c8517b469a119d267be5645686309c6e6736dbd93940707cc9143d3cf29f1b877ff340e2cb2d259cf
#print(uncompressed_key)

######################################


# this is taken from "parse 15 blocks" test in relay.js 
public_keys = []
with open('tmp_keys_for_python.json') as f:
    public_keys = json.load(f)

uncompressed_key_parts = {}
first_parts = []
second_parts = []
for key in public_keys:
    uncompressed = uncompress(key)
    uncompressed_part_0 = "0x" + uncompressed[2:66]
    uncompressed_part_1 = "0x" + uncompressed[66:130]
    first_parts.append(uncompressed_part_0)
    second_parts.append(uncompressed_part_1)
uncompressed_key_parts["x"] = first_parts
uncompressed_key_parts["y"] = second_parts

with open('uncompressed_keys.json', 'w+') as outfile:
    json.dump(uncompressed_key_parts, outfile)