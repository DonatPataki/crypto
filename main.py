from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from time import time
import hashlib
import json
from merklelib import MerkleTree, beautify
import pprint
import datetime

class Transaction(object):
    def __init__(self, amount, sender, receiver):
        self.amount = amount
        self.sender = sender
        self.receiver = receiver
        self.time = time()
        self.hash = None
    
    def sign(self, privateKey):
        message = self.serialize()
        self.hash = privateKey.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
    
    def verify(self):
        message = self.serialize()
        self.sender.verify(self.hash, message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
    
    def serialize(self):
        senderPem = self.sender.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        receiverPem = self.receiver.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        message = str(self.amount) + str(senderPem) + str(receiverPem) + str(self.time)
        return bytes(message, 'utf-8')

class Block(object):
    def __init__(self, previousBlockHash, transactions, tree):
        self.previous = previousBlockHash
        self.transactions = transactions
        self.nonce = 0
        self.tree = tree
        while True:
            self.hash = self.calculateHash()
            if self.hash[0:4] == '0000':
                break
            self.nonce += 1
    
    def calculateHash(self):
        hashString = str(self.previous) + self.tree.merkle_root + str(self.nonce)
        hashEncoded = json.dumps(hashString, sort_keys=True).encode()
        return hashlib.sha256(hashEncoded).hexdigest()

class Blockchain(object):
    def __init__(self):
        self.chain = []
    
    def getLastBlockHash(self):
        if len(self.chain) == 0:
            return ''
        else:
            return self.chain[-1].hash
    
    def addBlock(self, block):
        self.chain.append(block)

    def jsonEncode(self):
        chainJson = []
        for block in self.chain:
            blockJson = {}
            blockJson['hash'] = block.hash
            blockJson['previous'] = block.previous
            blockJson['nonce'] = block.nonce
            blockJson['treeRoot'] = block.tree.merkle_root

            """ transactionListJson = []
            for transaction in block.transactions:
                transactionJson = {}
                transactionJson['hash'] = transaction.hash
                transactionJson['amount'] = transaction.amount
                transactionJson['sender'] = transaction.sender
                transactionJson['receiver'] = transaction.receiver
                transactionJson['time'] = datetime.datetime.fromtimestamp(transaction.time).strftime('%Y. %m. %d. %H:%M:%S')
                transactionListJson.append(transactionJson)
            blockJson['transactions'] = transactionListJson """
            chainJson.append(blockJson)
        return chainJson

class Wallet(object):
    def __init__(self):
        self.privateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.publicKey = self.privateKey.public_key()
        self.balance = 100
    
    def sendMoney(self, amount, receiverPublicKey):
        transaction = Transaction(amount, self.publicKey, receiverPublicKey)
        transaction.sign(self.privateKey)
        return transaction

def mine(transactions):
    pendingTransactions = []
    transactionHashes = []
    for transaction in transactions:
        transaction.verify()
        pendingTransactions.append(transaction)
        transactionHashes.append(transaction.hash)
    tree = MerkleTree(transactionHashes)
    global blockchain
    newBlock = Block(blockchain.getLastBlockHash(), pendingTransactions, tree)
    blockchain.addBlock(newBlock)

blockchain = Blockchain()

satoshi = Wallet()
bob = Wallet()
alice = Wallet()
cecil = Wallet()

transactions = []

transactions.append(satoshi.sendMoney(10, bob.publicKey))
transactions.append(bob.sendMoney(20, satoshi.publicKey))
transactions.append(satoshi.sendMoney(30, alice.publicKey))
transactions.append(cecil.sendMoney(40, satoshi.publicKey))

mine(transactions)

transactions = []

transactions.append(satoshi.sendMoney(10, bob.publicKey))
transactions.append(bob.sendMoney(20, satoshi.publicKey))
transactions.append(satoshi.sendMoney(30, alice.publicKey))

mine(transactions)

transactions = []

transactions.append(satoshi.sendMoney(10, bob.publicKey))

mine(transactions)

pp = pprint.PrettyPrinter(indent=4)
pp.pprint(blockchain.jsonEncode())
