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
#compressed_key = '0314fc03b8df87cd7b872996810db8458d61da8448e531569c8517b469a119d267'
compressed_key = '02c0ded2bc1f1305fb0faac5e6c03ee3a1924234985427b6167ca569d13df435cf'
y_parity = int(compressed_key[:2]) - 2
x = int(compressed_key[2:], 16)
a = (pow_mod(x, 3, p) + 7) % p
y = pow_mod(a, (p+1)//4, p)
if y % 2 != y_parity:
    y = -y % p
uncompressed_key = '04{:x}{:x}'.format(x, y)
print(uncompressed_key)
## should get 0414fc03b8df87cd7b872996810db8458d61da8448e531569c8517b469a119d267be5645686309c6e6736dbd93940707cc9143d3cf29f1b877ff340e2cb2d259cf
