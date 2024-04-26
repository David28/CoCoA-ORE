from copy import copy
import re
from unittest import result
from cripto import *  # decrypt_aes
from ds import *


class VulnerabilityDetector(object):

    def __init__(self, data, aeskey):
        self.ds = data
        self.output = []
        self.path = []
        self.visited = []
        self.alg = AESCipher(aeskey)
        #check if any entry has more than one value
        # for k, v in self.ds.data.items():
        #     if len(v) > 1:
        #         print("Warning: Multiple values for key " + k)

    #depth first search sse
    def sse_search(self,end, start, cur_rndkey, line=None, flow=0, order=0, type=0):
        if line:
            self.path.append((start, line, flow, order, type))

        counter = 1
        key_ind = encrypt(start,str(counter))
        if key_ind not in self.ds.data or start == end:
            self.output.append(copy(self.path))
            return
        counter = 1
        while True:
            
            key_ind = encrypt(start,str(counter))
            if key_ind not in self.ds.data:
                break
            val = self.ds.data[key_ind][0]
            val_ind = AESCipher(cur_rndkey).decrypt(val)
            val_ind = MyEncryptedValue._deserialize(val_ind)

            currLine = val_ind.get_line()
            currFlow = val_ind.get_flow()
            currOrder = val_ind.get_order()
            currType = val_ind.get_type()
            currToken = val_ind.get_det_key()
            currRndKey = val_ind.get_rnd_key()

            if currToken not in self.visited:
                self.visited.append(currToken)
                if not line:
                    self.path = [None]
                    self.path[0] = (start, currLine, currFlow,
                                    currOrder, currType)
                self.sse_search(end, currToken.type,currRndKey,
                            currToken.lineno, currFlow, currOrder, currType)
                self.path.pop()
                self.visited.remove(currToken)
            counter += 1
        return


        


    def search(self, end, start, line=None, flow=0, order=0, type=0):
        if line:
            self.path.append((start, line, flow, order, type))

        if start == end or start not in self.ds.data:
            self.output.append(copy(self.path))
            return

        val = self.ds.data[start]
        for v in val:
            currToken = v.get_token()
            currLine = v.get_line()
            currFlow = v.get_flow()
            currOrder = v.get_order()
            currType = v.get_type()
            if v.get_token() not in self.visited:
                self.visited.append(currToken)
                if not line:
                    self.path = [None]
                    self.path[0] = (start, currLine, currFlow,
                                    currOrder, currType)
                self.search(end, currToken.type,
                            currToken.lineno, currFlow, currOrder, currType)
                self.path.pop()
                self.visited.remove(currToken)

    def detection(self,start, end, sans, init_rnd_key = None):
        if init_rnd_key:
            self.sse_search( start,end, init_rnd_key)
        else:
            self.search(start, end)
        # operations over output
        #for x in self.output:
        #    print(x)
        final = {}
        group_by_vulns = {}
        myresult = []

        # tirar listas vazias
        self.output = [x for x in self.output if x]
        # agrupar por vulnerabilidades
        # usar estrutura especial para poder usar ORE probabilistico
        for i in self.output:
            if ore_tuple(i[0]) in group_by_vulns:
                group_by_vulns[ore_tuple(i[0])].append(i)
            else:
                group_by_vulns[ore_tuple(i[0])] = [i] 

        for k, v in group_by_vulns.items():
            # remove substitutions after vuln
            for i in v:
                lowest = i[0][1]
                for j in i[1:]:
                    if j[1] > lowest:
                        try:
                            v.remove(i)
                        except:
                            pass
                    else:
                        lowest = j[1]
            # depth checker
            # for i in range(1, max(len(x) for x in v)):
            #     for j in range(0, len(v)):z
            #         continue
            # find closest path to vulnerability
            best_match = None
            for i in range(1, max(len(x) for x in v)):
                closest = None
                for j in range(0, len(v)):
                    if i < len(v[j]):
                        if not closest:
                            closest = v[j][i]
                            best_match = v[j]
                        elif v[j][i][1] > closest[1]: #TODO: Confirmar se v[0][0][1] - v[j][i][1] < v[0][0][1] - closest[1] <=> v[j][i][1] > closest[1]
                            closest = v[j][i]
                            best_match = v[j]
            #print(closest)
            #print(best_match)   
            # print("_______________________")
            if best_match[0] in final:
                final[best_match[0]].append(best_match)
            else:
                final[best_match[0]] = best_match
        #######################################
        for _, v in final.items():
            myresult.append(v)
        accused = -1
        base_depth = self.ds.get("BASE_DEPTH")[0]
        for _, i in final.items():
            boolskip = True
            for j in i:
                if j[2] > base_depth: #TODO: Com ORE precisa-se de este valor base cifrado antes era só 0
                    for loles in i[2:]:
                        # se ha alguma atribuicao
                        if loles[2] == i[0][2] and loles[3] == i[0][3] and loles[4] == i[0][4]:
                            boolskip = False
                    if boolskip:
                        atual = group_by_vulns[ore_tuple(i[0])]
                        # ver se eh tudo fora de control flow
                        for verify in atual:
                            allzero = True
                            for token in verify:
                                if token[2] != base_depth:
                                    allzero = False
                                    break
                            if allzero:
                                myresult.append(verify)
                        for verify in atual:
                            if verify != i:
                                for token in verify:
                                    # se nmr de linha eh acima
                                    if token[1] <= j[1]:
                                        if token[3] != j[3]:
                                            myresult.append(verify)
                                        elif token[3] == j[3] and token[4] != j[4]:
                                            myresult.append(verify)
                                        elif token[3] == j[3] and token[4] == j[4] and token[2] != j[2]:
                                            myresult.append(verify)
                    break
        # analisar caminhos
        # tirar logo o q n acaba em input
        myresult = [x for x in myresult if x[-1][0] == start]
        # # other check and control flow
        remall = []
        aux = []
        i = 0
        while i < len(myresult):
            for j in myresult[i]:
                if j[0] == sans:
                    vuln = myresult[i][0]
                    # neste caso a sanitization esta no mesmo cf q a e sens
                    if j[2] == vuln[2] and j[3] == vuln[3] and j[4] == vuln[4]:
                        remall.append(myresult[i][0])
                    else:
                        aux.append(myresult[i])
            i += 1

        myresult = [x for x in myresult if x not in aux]
        myresult = [x for x in myresult if x[0] not in remall]
        # tirar lista vazias(pa ficar bonito)
        myresult = [x for x in myresult if x != []]
        finalresult = []
        for x in myresult:
            if x not in finalresult:
                finalresult.append(x)

        return finalresult


#hashable tuple that may contain probailistic ORE values
#Allow probabilistic ORE values to have the same hash
class ore_tuple:
    vals = []
    rep_key = []
    def __init__(self, tup):
        self.tup = tup
        self.hash_rep = list(tup)
        for i in range(len(tup)):
            if len(ore_tuple.vals) <= i:
                ore_tuple.vals.append({})
                ore_tuple.rep_key.append(0)
            if isinstance(tup[i], OreVal):
                rep = None
                for k, v in ore_tuple.vals[i].items():
                    if v == tup[i]:
                        rep = k

                        break
                if rep is None:
                    rep = ore_tuple.rep_key[i]
                    ore_tuple.vals[i][rep] = tup[i]
                    ore_tuple.rep_key[i] += 1
                self.hash_rep[i] = rep
        self.hash_rep = tuple(self.hash_rep)
    def __eq__(self, other):
        for i in range(len(self.tup)):
            if self[i] != other[i]:
                return False
        return True

    def __hash__(self):
        return hash(self.hash_rep)
    
    #index acess   
    def __getitem__(self, key):
        return self.tup[key]