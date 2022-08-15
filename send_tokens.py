#!/usr/bin/python3

from algosdk.v2client import algod
from algosdk.v2client import indexer
from algosdk import account
from algosdk.future import transaction
import time

def connect_to_algo(connection_type=''):
    #Connect to Algorand node maintained by PureStake
    algod_token = "B3SU4KcVKi94Jap2VXkK83xx38bsv95K5UZm2lab"
    
    if connection_type == "indexer":
        # TODO: return an instance of the v2client indexer. This is used for checking payments for tx_id's
        algod_address = "https://testnet-algorand.api.purestake.io/idx2"
        purestake_token = {'X-Api-key': algod_token}
        return indexer.IndexerClient(algod_token, algod_address, purestake_token)
    
    else:
        # TODO: return an instance of the client for sending transactions
        # Tutorial Link: https://developer.algorand.org/tutorials/creating-python-transaction-purestake-api/
        algod_address = "https://testnet-algorand.api.purestake.io/ps2"
        purestake_token = {'X-Api-key': algod_token}
#         mnemonic_phrase = "judge machine copper sick invest rule skate pioneer glue effort deny correct negative shop soccer join six merry knee parent maid gasp enhance abstract senior"
        
        return algod.AlgodClient(algod_token, algod_address, purestake_token)

def send_tokens_algo( acl, sender_sk, txes):
    params = acl.suggested_params()
    
    # TODO: You might want to adjust the first/last valid rounds in the suggested_params
    #       See guide for details
    
    # TODO: For each transaction, do the following:
    #       - Create the Payment transaction 
    #       - Sign the transaction
    
    # TODO: Return a list of transaction id's
    
    sender_pk = account.address_from_private_key(sender_sk)
    
   
    tx_ids = []
    for i,tx in enumerate(txes):
        
        print("Let's send an Algorand transaction!")
        
        receiver_pk = tx['receiver_pk']
        amount = tx['tx_amount']
        
        unsigned_tx = transaction.PaymentTxn(sender_pk,params,receiver_pk, int(amount))

        # TODO: Sign the transaction
        signed_tx = unsigned_tx.sign(sender_sk)
        
        try:
#             print(f"Sending {tx['tx_amount']} microalgo from {sender_pk} to {tx['receiver_pk']}" )
            # TODO: Send the transaction to the testnet
            
            acl.send_transaction(signed_tx)
            tx_id = unsigned_tx.get_txid()
            tx_ids.append(tx_id)
            time.sleep(5)
            txinfo = wait_for_confirmation_algo(acl, txid=tx_id )
#             print(f"Sent {tx['tx_amount']} microalgo in transaction: {tx_id}\n" )
            
        except Exception as e:
            print(e)
        
        params.first += 1

    return tx_ids

# Function from Algorand Inc.
def wait_for_confirmation_algo(client, txid):
    """
    Utility function to wait until the transaction is
    confirmed before proceeding.
    """
    last_round = client.status().get('last-round')
    txinfo = client.pending_transaction_info(txid)
    while not (txinfo.get('confirmed-round') and txinfo.get('confirmed-round') > 0):
        time.sleep(5)
        print("Waiting for confirmation")
        last_round += 1
        client.status_after_block(last_round)
        txinfo = client.pending_transaction_info(txid)
    print("Transaction {} confirmed in round {}.".format(txid, txinfo.get('confirmed-round')))
    return txinfo

##################################

from web3 import Web3
from web3.middleware import geth_poa_middleware
from web3.exceptions import TransactionNotFound
import json
import progressbar


def connect_to_eth():
    IP_ADDR='3.23.118.2' #Private Ethereum
    PORT='8545'

    w3 = Web3(Web3.HTTPProvider('http://' + IP_ADDR + ':' + PORT))
    w3.middleware_onion.inject(geth_poa_middleware, layer=0) #Required to work on a PoA chain (like our private network)
    w3.eth.account.enable_unaudited_hdwallet_features()
    if w3.isConnected():
        return w3
    else:
        print( "Failed to connect to Eth" )
        return None

def wait_for_confirmation_eth(w3, tx_hash):
    print( "Waiting for confirmation" )
    widgets = [progressbar.BouncingBar(marker=progressbar.RotatingMarker(), fill_left=False)]
    i = 0
    with progressbar.ProgressBar(widgets=widgets, term_width=1) as progress:
        while True:
            i += 1
            progress.update(i)
            try:
                receipt = w3.eth.get_transaction_receipt(tx_hash)
            except TransactionNotFound:
                continue
            break 
    return receipt


####################
def send_tokens_eth(w3,sender_sk,txes):
    print("CP1")
    sender_account = w3.eth.account.privateKeyToAccount(sender_sk)
    print("CP2")
    sender_pk = sender_account._address

    print("CP3")
        
    # TODO: For each of the txes, sign and send them to the testnet
    # Make sure you track the nonce -locally-
    
    
    starting_nonce = w3.eth.get_transaction_count(sender_pk,"pending")
    tx_ids = []

    print("CP4")
    
    for i,tx in enumerate(txes):
        
        receiver_pk = tx['receiver_pk']
        tx_amount = tx['tx_amount']
        
        print("CP5")

        # Your code here
        tx_dict = {
                'nonce': starting_nonce+i, #Locally update nonce
                'gasPrice':w3.eth.gas_price,
                'gas': w3.eth.estimate_gas( { 'from': sender_pk, 'to': receiver_pk, 'data': b'', 'amount': tx_amount } ),
                'to': receiver_pk,
                'value': tx_amount,
                'data':b'' }
        
        print("CP6")
        
        print(tx_dict)
        
        signed_txn = w3.eth.account.sign_transaction(tx_dict, sender_sk)
        print("Let's send an Ethereum transaction!")
        tx_id = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        print("CP7")
        tx_ids.append(tx_id)
    
    return tx_ids
