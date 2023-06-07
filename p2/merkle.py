from typing import Optional, List
import numpy as np
import hashlib

debug = True



def verify(obj: str, proof: str, commitment: str) -> bool:
    def hash(a, b):
        a = int(a, base=16)
        b = int(b, base=16)
        to_hash = int(a + b).to_bytes(64, 'big')
        r = hashlib.sha256(to_hash).hexdigest()
        return r

    proof_list = proof.split(' ')
    output = obj
    for i in proof_list:
        output = hash(output, i)

    return output == commitment[2:]


class Prover:
    def __init__(self, sig=False):
        """
        state should include array (sized first time build merkle tree runs)...
        """
        self._data = None
        self.first_leaf_ind = None
        self.round_up = lambda x: -1 * (-x // 1)  # ceiling round
        self.d = None  # x is list
        self.size = None
        self.commitment = None
        self.sig = sig

    def hash(self, *nodes: int):

        assert len(nodes) < 3, nodes
        assert type(nodes) == tuple, nodes
        nodes = sorted(nodes)
        p = self.get_parent_index(nodes[0])
        j = self.get_dj_from_seq(p)[1]
        a = self._data[nodes[0]]
        b = self._data[nodes[1]]

        if not self.sig:
            to_hash = int(a + b).to_bytes(64, 'big')
        else:
            j = int(j).to_bytes(64, 'big')
            j = ''.join([f'{i:0>4b}' for i in j])
            a = int(a).to_bytes(64, 'big')
            a = ''.join([f'{i:0>4b}' for i in a])
            b = int(b).to_bytes(64, 'big')
            b = ''.join([f'{i:0>4b}' for i in b])
            to_hash = (j + a + b).encode()
            # print(to_hash)

        return hashlib.sha256(to_hash)

    def get_sibling_index(self, node: int):
        """
        :arg node: index of node is key
        """
        if node % 2 == 0:
            left = node - 1
            return left
        else:
            right = node + 1
            return right

    def get_children_index(self, node: int):
        """
        can only return one parent's left or right chile=d
        :arg node: index of node is key
        """
        return ((2 * node) + 1), ((2 * node) + 2)

    def set_parent_of(self, child: int):
        sib = self.get_sibling_index(child)

        v = self.hash(child, sib).hexdigest()
        p = self.get_parent_index(child)
        self._data[p] = int(v, base=16)

    def get_parent_index(self, node: int):
        """
        :arg which: 0 for left; 1 for right
        :arg node: index of node of child

        Will 'make' and return index of parent. if no parent, will make one with sibling (
        depending on even/odd)
        """
        assert node != 0, node
        return (node - 1) // 2

    @staticmethod
    def get_seq_ind_from_dj(dj: tuple) -> int:
        (d, j) = dj
        return int(2 ** d + j - 1)

    @staticmethod
    def get_dj_from_seq(ind: int) -> int:
        if ind == 0:
            return (0, 0)
        d = int(np.log2(ind) // 1)
        j = ind - 2 ** d
        return (d, j)

    def get_leaf(self, index: int) -> Optional[str]:
        """
        return leaf at index z.....since whole thing is on an array, would have to get total size,
        would have to be fixed length. h = n + 1. count from
        first tree index of last row = 2^n - 1
        tree index = first + leaf index
        """
        ind = int(self.first_leaf_ind + index)
        assert ind < len(self._data)
        if self._data[ind] == 0:
            return
        return hex(self._data[ind])

    # Build a merkle tree and return the commitment
    def build_merkle_tree(self, objects: List[str]) -> str:
        """
        input list of strings. strings are ordered/ indexed. not sorted...they are hashes of the
        blocks. produces merkle tree (array based)
        Sizing of np.array: 2^(n+1) - 1; n = round(log_2 (leaf count))

        returns commitment (root hash)
        """
        # even out
        if len(objects) % 2 != 0:
            objects.append(objects[-1])

        # Calculate Full Size
        self.d = int(self.round_up(np.log2(len(objects))))  # d is starting from 1?
        self.size = int(2 ** (self.d + 1) - 1)  # sizeing up?
        self._data = np.zeros(self.size, dtype=object)

        # assign leaves
        self.first_leaf_ind = int(2 ** self.d - 1)
        i = int(self.first_leaf_ind)
        j = int(i + len(objects))
        objects = [int(x, base=16) for x in objects]
        self._data[i:j] = objects
        inds = [i for i in range(i, j)]

        def build_retrieve(list_of_inds):

            if len(list_of_inds) == 1:
                self.commitment = hex(self._data[0])
                return self.commitment

            if len(list_of_inds) % 2 != 0:
                list_of_inds.append(list_of_inds[-1])

            # print(list_of_inds)

            parents = list()
            for i, k in enumerate(list_of_inds):
                if i % 2 == 0:
                    continue
                self.set_parent_of(k)
                parents.append(self.get_parent_index(k))

            return build_retrieve(parents)

        return build_retrieve(inds)

    def generate_proof(self, index: int) -> Optional[str]:
        """
        input: LEAF index.
        get sibling nodes all the way up
        """
        index = int(self.first_leaf_ind + index)
        assert index < len(self._data)
        # list begin: get leaf' sibling
        if self._data[index] == 0:
            return
        proof_ind_list = list()
        proof_ind_list.append(
            self.get_sibling_index(index)
        )

        def get_uncles(node: int):
            # print(node)
            p = self.get_parent_index(node)
            if p == 0:
                return
            u = self.get_sibling_index(p)
            proof_ind_list.append(u)
            get_uncles(u)

        get_uncles(index)  # generates index array of proof. includes root
        # print(proof_ind_list)

        return ' '.join([hex(self._data[i]) for i in proof_ind_list]) \
            if not self.sig \
            else ''.join([hex(self._data[i])[2:] for i in proof_ind_list])
