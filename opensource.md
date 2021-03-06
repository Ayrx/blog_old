---
layout: page
title: Open Source Contributions
---

I am a huge proponent of open source. Here are the projects I contribute to.

# PyCA's cryptography

[cryptography](https://cryptography.io/en/latest/) is a Python library that
exposes cryptographic recipes and primitives. It is an actively developed
library that supports a wide range of Python versions from 2.6 - 3.4 as well
as PyPy. The library has a sane API, good documentation and supports modern
algorithms.

My contribution to the library includes adding support for algorithms like
HOTP, TOTP, CMAC and HKDF expand mode. I also help improve documentation and
review patches. A full list of my merged commits can be found on
[GitHub](https://github.com/pyca/cryptography/commits?author=Ayrx).

# tlsenum

tlsenum is a tool I wrote that attempts to enumerate what TLS cipher suites a
server supports and list them in order of priority. It also performs various
tests that checks things like supported versions of TLS and support for
TLS-level compression. It is a work in progress but I eventually hope to turn
tlsenum into a useful tool for auditing TLS configurations.

# python-aead

aead is a Python library I wrote that provides authenticated encryption with
associated data (AEAD) wrapped up in a simple to use API. It is essentially
`AES_128_CBC` and `HMAC_SHA_256` composed with an encrypt-then-mac construction
and relies on PyCA's `cryptography` library for the cryptographic primitives.

See my [blog post]({% post_url 2014-12-29-python-aead %}) about the library for
more information.
