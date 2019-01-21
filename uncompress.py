from pprint import pprint

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
    uncompressed_key = '04{:x}{:x}'.format(x, y)
    return uncompressed_key


#####################################################################################
compressed_key = '02c0ded2bc1f1305fb0faac5e6c03ee3a1924234985427b6167ca569d13df435cf'
uncompressed_key = uncompress(compressed_key)
## should get 0414fc03b8df87cd7b872996810db8458d61da8448e531569c8517b469a119d267be5645686309c6e6736dbd93940707cc9143d3cf29f1b877ff340e2cb2d259cf
##print(uncompressed_key)

######################################

# this is taken from "parse 15 blocks" test in relay.js 
public_keys = [
  '02e65e41cb9ee12e23af44d32c337788253765eee9cd5c5b39900bf22e6d39dab1',
  '028d316c09c917eecbd8da03a695029a63dc3a4294c75c254af7d00078709b1107',
  '02fc35aa95c03e0e75553f2dc670e476e7cbceb0bd9962dd637629e307e6366336',
  '027488fb8ad5080f9ff609501b1b392858061e9cc4d7a7e98f8c1dcfb076c613ab',
  '032aeec24bd317fffed0cd787efaf3cd8b7454fcf1dc3be8d4d6b0d6d337282eca',
  '03de2988ea5bf8c7d01283f127e9f7a9b3d40fb95a618e78975e210995fcfbff49',
  '0383a91696b1538d01f80a7ffabc105aa4eb0a2e69798585c07112e37f2c982e76',
  '030865d02cc3433ac84a94f3834ca39e0cc54446ab3da13e29d3cfc2cc9341c8d5',
  '02f19818348f231392e0e77ee0d30424f16f213fa44d143efb0944a9e698e6d1c4',
  '037fbdb976fea057a5cbb6cb72229f02f36c02635e98ee4ccf555b4c34cc8fbf38',
  '0226dfc6402e9ffba01f798814c93ab2aac31e1794409f089525b09deded0eddc3',
  '029d65a2751be09a3dcd5df1ed634c13fb11c4a9e31f726a4435d74b9f75c63dd6',
  '038b9c2183652437df1294edc1654a7fc3885e9ff849678be67ce79082a566b364',
  '027c30a8443026f4c518fb1659aa6e41f15a21b44c075cd98e88e0939ece61d906',
  '03d09cdc55b989bf3c1b728dc39f049fffe1eb88376b5eeee7ab3ee9fbf382cb26',
  '02f19e790aaf9335cf1ab21a32aa986e4c30ec1360f8e69e2e39ea28af606813df',
  '02c004a5f66932f3bdc28029071b982c23ab78ed17018bbeec277b9cb8e2d50754',
  '03d322a86189958f2ac52029908b02b8c0ae2262eae21d44b3c1c29ad1e4cb018f',
  '02d5d8e44856678a456b05e0359b8925bc4cda9191fd71b95a3550764c51ed3bc8',
  '039579e7254e9dc8f4be4e91f4faced3861e2cae56163bee1cdc0ab302ecc7c9da',
  '026be42a9296f30dd30f72c714591a7ced3b8307ac575f0353848b2643c5999061'
]

uncompressed_key_parts = {}
first_parts = []
second_parts = []
for key in public_keys:
    uncompressed = uncompress(key)
    uncompressed_part_0 = "0x" + uncompressed[2:65]
    uncompressed_part_1 = "0x" + uncompressed[66:129]
    first_parts.append(uncompressed_part_0)
    second_parts.append(uncompressed_part_1)
uncompressed_key_parts["first_parts"] = first_parts
uncompressed_key_parts["second_parts"] = second_parts
# pprint(uncompressed_key_parts)

import json
with open('uncompressed_keys.json', 'w+') as outfile:
    json.dump(uncompressed_key_parts, outfile)