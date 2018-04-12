#!/usr/bin/env python
from jwcrypto import jwk, jwe
import json
key = jwk.JWK.generate(kty='oct', size=256)
print(key.export())

