#!/usr/bin/env python3
from jsonrpc import ServiceProxy
access = ServiceProxy("http://127.0.0.1:8332")
pwd = input("Enter old wallet passphrase: ")
pwd2 = input("Enter new wallet passphrase: ")
access.walletpassphrasechange(pwd, pwd2)
