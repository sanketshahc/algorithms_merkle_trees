import string
import random
import hashlib
import numpy as np
import re, random

from p2.merkle import *


# return the hash of a string
def SHA(s: string) -> string:
    return hashlib.sha256(s.encode()).hexdigest()


# transfer a hex string to integer
def toDigit(s: string) -> int:
    return int(s, 16)


# generate 2^d (si^{-1}, si) pairs based on seed r
def KeyPairGen(d: int, r: int) -> dict:
    pairs = {}
    random.seed(r)
    for i in range(1 << d):
        cur = random.randbytes(32).hex()
        while cur in pairs:
            cur = random.randbytes(32).hex()
        pairs[cur] = SHA(cur)
    return pairs


class MTSignature:
    def __init__(self, d, k):
        self.d = d
        self.k = k  # determines how many leaves from the tree
        self.treenodes = [None] * (d + 1)
        for i in range(d + 1):
            self.treenodes[i] = [None] * (1 << i)
        self.sk = [None] * (1 << d)
        self.pk = None  # same as self.treenodes[0][0]
        self.r = None
        self.P = None

    # Populate the fields self.treenodes, self.sk and self.pk. Returns self.pk.
    def KeyGen(self, seed: int) -> string:
        """
        :arg seed: seed integer to set self.r
        :return : string of self.pk

        - set the self.r properties
        - call KeyPariGen(self.d, self.r), returns dict of preimage / image pairs.
        - set the keys of dict as the private kay self.sk.
        - set the values of dict as the leaf node values
        - then buildmerkletree with prover class...the hashing however must be different.
        - It must take the j index, and it must concatenate rather than add...the return is the pk
        - then for each (d.j) index in our treenodes shell array, get the _data index,
        and then replace the Nones with real data.
        """

        self.r = seed
        keychain = KeyPairGen(self.d, self.r)
        assert len(self.sk) == len(keychain.keys())
        self.sk = list(keychain.keys())
        assert len(self.treenodes[-1]) == len(keychain.values())
        # self.treenodes[self.d] = [s[2:] for s in keychain.values()]
        P = Prover(sig=True)
        self.pk = P.build_merkle_tree(list(keychain.values()))[2:]

        for d, row in enumerate(self.treenodes):
            for j, _ in enumerate(row):
                i = P.get_seq_ind_from_dj((d, j))
                # print(d,j,i)
                v = hex(P._data[i])
                self.treenodes[d][j] = v[2:]

        self.P = P
        return self.pk

    # Returns the signature. The format of the signature is as follows: ([sigma], [SP]).
    # The first is a sequence of sigma values and the second is a list of sibling paths.
    # Each sibling path is in turn a d-length list of tree node values. 
    # All values are 64 bytes. Final signature is a single string obtained by concatentating all values.
    def Sign(self, msg: string) -> string:
        """
        :arg msg: a string of text

        - intake string, concat with the binary string of the index j of k.
        - for each of k, zj = hash ( bin(j) + m) mod 2**d.
        - take this private key
        - concat them.
        - get all proof strings of the leaves by using the  methods of PRover.
        - return

        """
        z_list = list()
        sigma = list()
        sp = list()

        for j in range(1, self.k + 1):
            j = j.to_bytes(64, 'big')
            j = ''.join([f'{i:0>4b}' for i in j])
            s = j + msg
            # print(s)
            h = SHA(s)
            # print(h)
            z_list.append(
                toDigit(h) % 2 ** self.d
            )

        for z in z_list:
            # print(z)
            sigma.append(self.sk[z])
            sp.append(self.P.generate_proof(z))

        return ''.join(sigma + sp)


def clash():
    def check(a, b):
        x = len(a) < 10 or len(b) < 10
        y = a == b
        return x + y

    def process(a):
        a = re.sub("[0-9:]+", "", a)
        a = re.sub(" +", " ", a)
        # a = re.sub("[\';\"(),.-]", "", a)
        a = " ".join(a.split(" ")[:12])
        a = re.sub("(^ +)|( +$)", "", a)
        a = a.lower()
        return a

    M = MTSignature(10, 2)
    M.KeyGen(2022)
    with open('../bible.txt') as f:
        lines = f.readlines()
        y, z = 0, 1
        while y != z:
            a, b = "", ""
            while check(a, b) > 0:
                i, j = random.randint(0, 100181), random.randint(0, 100181)
                a = process(lines[i])
                b = process(lines[j])

            y = M.Sign(a)
            z = M.Sign(b)

        print(i, j)
        print(a, "\n", b)
