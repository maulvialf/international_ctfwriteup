#!/bin/python
import gmpy
import base64
from Crypto.Util.number import *
n64 =
e64 =
n = bytes_to_long(base64.b64decode(n64))
e = bytes_to_long(base64.b64decode(e64))
file64 =
chiper = bytes_to_long(base64.b64decode(file64))
gs = gmpy.mpz(chiper)
gm = gmpy.mpz(n)
g3 = gmpy.mpz(3)
print 'n : ', n
print 'e : ', e
mask =
gmpy.mpz(0x8080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808000)
test = 0
while True:
	if test == 0:
		gs = gs
	else:
		gs += gm
	root,exact = gs.root(g3)
	if (root & mask).bit_length() < 8:
		print root
		break
print '\n',hex(int(root))[2:-1].decode('hex')