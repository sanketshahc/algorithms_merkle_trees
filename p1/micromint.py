## Problem 1
import numpy as np
import pandas as pd
import hashlib
import os
import random

## Watermark
forged_nid = "st2901"
nid = "ss4228"
watermark = ''.join(format(x, 'b') for x in bytearray(nid, 'ascii'))
watermark = watermark[:10]
watermark = int(watermark, base=2)


class Hash_Table(dict):
    """
    key: hash
    """

    def __init__(self):
        super(Hash_Table, self).__init__()
        self.n = 7
        self.k = 4

    def update(self, entry: dict):
        for key, val in entry.items():
            key = key[:self.n]
            if not super().get(key):
                super().update({key: [val]})
                return False, None
            else:
                coins = super().get(key)
                coins.append(val)
                super().update({key: coins})
                # print("Clash:", key, coins)
                if len(coins) == self.k:
                    coins = [hex(c)[2:] for c in coins]
                    # print(super().get(key))
                    print(key)
                    # print("Coin Found:", coins)
                    return True, coins
                else:
                    return False, None

T = Hash_Table()

def clash():
    Coin = None
    loop = 0
    while not Coin:
        _coin = random.getrandbits(54)
        coin_i = (watermark << 54) | (_coin >> 10)
        hash = hashlib.sha256(coin_i.to_bytes(64, 'big')).hexdigest()[:7]
        x = T.update({hash: coin_i})
        if x[0]:
            Coin=x[1]
            # print(T.get(hash))
        loop += 1
        if loop % 1e6 == 0:
            print('loops:', loop)
    print(Coin)
    return Coin


if __name__ == '__main__':
    coin = clash()
    if not os.path.exists('p1'):
        os.mkdir('p1')
    with open('p1/coin.txt','w+') as f:
        f.writelines(s + '\n' for s in coin) # ridiculous
    with open('p1/forged-watermark.txt','w+') as f:
        f.write(forged_nid)
