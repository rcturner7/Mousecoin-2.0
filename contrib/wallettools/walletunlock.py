#!/usr/bin/env python3
from jsonrpc import ServiceProxy
access = ServiceProxy("http://127.0.0.1:8332")
pwd = input("Enter wallet passphrase: ")
access.walletpassphrase(pwd, 60)
