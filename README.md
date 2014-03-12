Conversion-GCC
==============

Various conversion code in the public domain (hex, Base64, etc.)

This is very bare, no-frills code that attempts to be nearly constant time (to reduce vulnerabilities to timing attacks) if the input is constant length, as it generally is for password hashing outputs (i.e. the outputBytes or hkLen should generally be the same for all your hashed passwords of a given version).

Currently includes:
bin2Hex
hex2Bin
bin2Base64   (RFC alphabet +/ with = padding)
