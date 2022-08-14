from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import math
import sys
import traceback
from algosdk import mnemonic
from algosdk import account
from web3 import Web3

# Generate private keys

w3 = Web3()

w3.eth.account.enable_unaudited_hdwallet_features()
# acct,mnemonic_secret_eth = w3.eth.account.create_with_mnemonic()

# with open('eth_mnemonic.txt', 'w') as f1:
#     f1.write(mnemonic_secret_eth)
# print("ETH Mnemonic:")
# print(mnemonic_secret_eth)
    
# algo_sk, algo_pk = account.generate_account()

# mnemonic_secret_alg = mnemonic.from_private_key(algo_sk)

# with open('alg_mnemonic.txt', 'w') as f2:
#     f2.write(mnemonic_secret_alg)

# print("ALG Mnemonic:")
# print(mnemonic_secret_alg)

# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

from models import Base, Order, TX
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

app = Flask(__name__)

""" Pre-defined methods (do not need to change) """

@app.before_request
def create_session():
    g.session = scoped_session(DBSession)

@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()

def connect_to_blockchains():
    try:
        # If g.acl has not been defined yet, then trying to query it fails
        acl_flag = False
        g.acl
    except AttributeError as ae:
        acl_flag = True
    
    try:
        if acl_flag or not g.acl.status():
            # Define Algorand client for the application
            g.acl = connect_to_algo()
    except Exception as e:
        print("Trying to connect to algorand client again")
        print(traceback.format_exc())
        g.acl = connect_to_algo()
    
    try:
        icl_flag = False
        g.icl
    except AttributeError as ae:
        icl_flag = True
    
    try:
        if icl_flag or not g.icl.health():
            # Define the index client
            g.icl = connect_to_algo(connection_type='indexer')
    except Exception as e:
        print("Trying to connect to algorand indexer client again")
        print(traceback.format_exc())
        g.icl = connect_to_algo(connection_type='indexer')

        
    try:
        w3_flag = False
        g.w3
    except AttributeError as ae:
        w3_flag = True
    
    try:
        if w3_flag or not g.w3.isConnected():
            g.w3 = connect_to_eth()
    except Exception as e:
        print("Trying to connect to web3 again")
        print(traceback.format_exc())
        g.w3 = connect_to_eth()
        
""" End of pre-defined methods """
        
""" Helper Methods (skeleton code for you to implement) """

def log_message(message_dict):
    msg = json.dumps(message_dict)

    # TODO: Add message to the Log table
    
    with open('server_log.txt', 'a') as log_file:
        log_file.write(msg)

def get_algo_keys(filename = "alg_mnemonic.txt"):
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the algorand public/private keys
    
#     with open(filename, 'r') as f:
#         mnemonic_secret = f.readline()
        
    mnemonic_secret = "judge machine copper sick invest rule skate pioneer glue effort deny correct negative shop soccer join six merry knee parent maid gasp enhance abstract senior"
        
    algo_sk = mnemonic.to_private_key(mnemonic_secret)
    algo_pk = mnemonic.to_public_key(mnemonic_secret)
    
#     print("algo_sk")
#     print(algo_sk)
#     print("algo_pk")
#     print(algo_pk)
 
    return algo_sk, algo_pk


def get_eth_keys(filename = "eth_mnemonic.txt"):
#     w3 = Web3()
    # TODO: Generate or read (using the mnemonic secret) 
    # the ethereum public/private keys
    
#     with open(filename, 'r') as f:
#         mnemonic_secret = f.readline()
    
    mnemonic_secret = "early alarm fatigue budget year fetch doll deal early goose scare bicycle"
    
    acct = w3.eth.account.from_mnemonic(mnemonic_secret)
    eth_pk = acct._address
    eth_sk = acct._private_key

    return eth_sk, eth_pk
  
def fill_order(new_order,txes=[]):
    # TODO: 
    # Match orders (same as Exchange Server II)
    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
    # Make sure that you end up executing all resulting transactions!

    print("Checkpoint 1")
    
    #Check if there are any existing orders that match the new order
    orders = session.query(Order).filter(Order.filled == None).all()
    
    print("Checkpoint 2")
    
    for existing_order in orders:
        
        # Check if currencies match
        if existing_order.buy_currency == new_order.sell_currency and existing_order.sell_currency == new_order.buy_currency:

            # Check if exchange rates match
            if existing_order.sell_amount * new_order.sell_amount >= new_order.buy_amount * existing_order.buy_amount:
                
                #If a match is found between order and existing_order do the trade
                existing_order.filled = datetime.now()
                new_order.filled = datetime.now()
                existing_order.counterparty_id = new_order.id
                new_order.counterparty_id = existing_order.id
                session.commit()
                break
    
    print("Checkpoint 3")
    
    if existing_order.buy_amount > new_order.sell_amount:

        buy_amount = existing_order.buy_amount - new_order.sell_amount
        sell_amount = existing_order.sell_amount / existing_order.buy_amount * buy_amount

        child_data = {'buy_currency': existing_order.buy_currency,
                       'sell_currency': existing_order.sell_currency,
                       'buy_amount': buy_amount,
                       'sell_amount': sell_amount,
                       'sender_pk': existing_order.sender_pk,
                       'receiver_pk': existing_order.receiver_pk,
                       'creator_id': existing_order.id,
                       'tx_id': existing_order.tx_id
                      }
        
        child_order = Order(**{f:child_data[f] for f in fields_child})
        session.add(child_order)
        session.commit()
        print("Child created")

    elif new_order.buy_amount > existing_order.sell_amount:
        #create order

        buy_amount = new_order.buy_amount - existing_order.sell_amount
        sell_amount = new_order.sell_amount / new_order.buy_amount * buy_amount

        child_data = {'buy_currency': new_order.buy_currency,
                       'sell_currency': new_order.sell_currency,
                       'buy_amount': buy_amount,
                       'sell_amount': sell_amount,
                       'sender_pk': new_order.sender_pk,
                       'receiver_pk': new_order.receiver_pk,
                       'creator_id': new_order.id,
                       'tx_id': existing_order.tx_id
                      }
        
        
        child_order = Order(**{f:child_data[f] for f in fields_child})
        session.add(child_order)
        session.commit()
        print("Child created")

def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print( f"Trying to execute {len(txes)} transactions" )
    print( f"IDs = {[tx['order_id'] for tx in txes]}" )
    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()
    
    if not all( tx['platform'] in ["Algorand","Ethereum"] for tx in txes ):
        print( "Error: execute_txes got an invalid platform!" )
        print( tx['platform'] for tx in txes )

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand" ]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum" ]

    # TODO: 
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table

    pass

""" End of Helper methods"""
  
@app.route('/address', methods=['POST'])
def address():
    
    print("New iteration")
    
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print( f"Error: no platform provided" )
            return jsonify( "Error: no platform provided" )
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print( f"Error: {content['platform']} is an invalid platform" )
            return jsonify( f"Error: invalid platform provided: {content['platform']}"  )
        
        if content['platform'] == "Ethereum":
            print("This is Ethereum")
            #Your code here
            
            eth_sk, eth_pk = get_eth_keys()
            print(eth_pk)
            
            return jsonify( eth_pk )
        
        if content['platform'] == "Algorand":
            print("This is Algorand")
            #Your code here
            
            algo_sk, algo_pk = get_algo_keys()
            print(algo_pk)

            return jsonify( algo_pk )

def check_sig(payload,sig):
    
    print("Check if signature is valid")
    
    payload_text = json.dumps(payload)
    pk = payload.get("sender_pk")
    
    if payload['platform'] == 'Ethereum':

        # Check Ethereum
        eth_encoded_msg = eth_account.messages.encode_defunct(text=payload_text)

        if eth_account.Account.recover_message(eth_encoded_msg, signature=sig) == pk:
            return True
        else:
            log_message(payload_text)
            return False
    else:
        # Check Algorand
        if algosdk.util.verify_bytes(payload_text.encode('utf-8'),sig,pk):
            return True                   
        else:
            log_message(payload_text)
            return False
        
        
@app.route('/trade', methods=['POST'])
def trade():
    print()
    print("New trade")
    print( "In trade", file=sys.stderr )
    connect_to_blockchains()
#     get_keys()
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = [ "sig", "payload" ]
        error = False
        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        # Your code here

        payload = content.get("payload")
        sig = content['sig']
        platform = payload.get("platform")
        tx_id = payload.get("tx_id")
        
        # 1. Check the signature
        
        print("Check the signature")
        
        if not check_sig(payload,sig):
            print("Return jsonify false")
            return jsonify( False )
        
        # 2. Add the order to the table
        
        print("Add order to table")
        
        # Create order

        order_data = {'sender_pk': payload.get("sender_pk"),
                      'receiver_pk': payload.get("receiver_pk"),
                      'buy_currency': payload.get("buy_currency"),
                      'sell_currency': payload.get("sell_currency"),
                      'buy_amount': payload.get("buy_amount"),
                      'sell_amount': payload.get("sell_amount"),
                      'tx_id': payload.get("tx_id"),
                      'signature': sig}

        new_order_fields = ['sender_pk','receiver_pk','buy_currency','sell_currency','buy_amount','sell_amount','signature','tx_id']
        new_order = Order(**{f:order_data[f] for f in new_order_fields})

        g.session.add(new_order)
        g.session.commit()
        
        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)
        
        print("Check tx")
        print(platform)
        if platform == "Ethereum":
            
            print("Platform is Ethereum")
            print(tx_id)
            
            tx = w3.eth.get_transaction(tx_id)
            
            print("Ethereum 1")
            print(tx)
            
            print("Ethereum 2")
            
            print(tx['from'])
            print(tx['to'])
            print(tx['hash'])
            print(tx['value'])

        
        else:
            print("Platform is Algorand")
            
#             payload.get("tx_id")

        # 3b. Fill the order (as in Exchange Server II) if the order is valid
        
        print("Fill order")
        fill_order(new_order)
        
        # 4. Execute the transactions
        
        # If all goes well, return jsonify(True). else return jsonify(False)
        print("Return jsonify true")
        return jsonify(True)

@app.route('/order_book')
def order_book():
    fields = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk", "sender_pk" ]
    
    # Same as before
    a_list = []
    
    for row in g.session.query(Order).all():
        a_dict = {'sender_pk':row.sender_pk,
                  'receiver_pk':row.receiver_pk,
                  'buy_currency':row.buy_currency,
                  'sell_currency':row.sell_currency,
                  'buy_amount':row.buy_amount,
                  'sell_amount':row.sell_amount,
                  'tx_id':row.tx_id,
                  'signature': row.signature}
        
        a_list.append(a_dict)

    result = {'data' : a_list}
                   
    return jsonify(result)

if __name__ == '__main__':
    app.run(port='5002')
