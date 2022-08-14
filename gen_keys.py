#!/usr/bin/python3

from algosdk import mnemonic
from algosdk import account
from web3 import Web3

w3.eth.account.enable_unaudited_hdwallet_features()
acct,mnemonic_secret = w3.eth.account.create_with_mnemonic()

with open('mnemonic.txt', 'w') as f:
    f.write(mnemonic_secret)

print(mnemonic_secret)

algo_sk, algo_pk = generate_account()
