# Viatcheslav Kagan 	311763213
# Liad Khamdadash		313299877

import pyDes
data = "DES Algorithm Implementation"
k = pyDes.des("DESCRYPT", pyDes.CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
d = k.encrypt(data)
print("Encrypted: %r" % d)
print("Decrypted: %r" % k.decrypt(d))
assert k.decrypt(d) == data