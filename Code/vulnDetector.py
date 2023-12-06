from copy import copy
import re
from unittest import result
from cripto import *  # decrypt_aes
from matplotlib.pyplot import close
from ds import *
flag = False


class VulnerabilityDetector(object):

    def __init__(self, data, aeskey):
        self.ds = data
        self.output = []
        self.path = []
        self.visited = []
        self.alg = AESCipher(aeskey)

    def search(self, end, start, line=None, flow=0, order=0, type=0):
        if line:
            self.path.append((start, line, flow, order, type))

        if start == end or start not in self.ds.data:
            self.output.append(copy(self.path))
            return

        val = self.ds.data[start]
        for v in val:
            if flag:
                v = MyValue._deserialize(self.alg.decrypt(v))
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

    def detection(self, start, end, sans):
        self.search(start, end, 0)
        # operations over output
        final = {}
        group_by_vulns = {}
        myresult = []

        # tirar listas vazias
        self.output = [x for x in self.output if x]

        # agrupar por vulnerabilidades
        for i in self.output:
            if i[0] in group_by_vulns:
                group_by_vulns[i[0]].append(i)
            else:
                group_by_vulns[i[0]] = [i]
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
            #     for j in range(0, len(v)):
            #         continue
            # find closest path to vulnerability
            for i in range(1, max(len(x) for x in v)):
                closest = None
                best_match = None
                for j in range(0, len(v)):
                    if i < len(v[j]):
                        if not closest:
                            closest = v[j][i]
                            best_match = v[j]
                        elif v[0][0][1] - v[j][i][1] < v[0][0][1] - closest[1]:
                            closest = v[j][i]
                            best_match = v[j]
            # print(closest)
            # print(best_match)
            # print("_______________________")
            if best_match[0] in final:
                final[best_match[0]].append(best_match)
            else:
                final[best_match[0]] = best_match
        #######################################
        for _, v in final.items():
            myresult.append(v)
        accused = -1
        for _, i in final.items():
            boolskip = True
            for j in i:
                if j[2] > 0:
                    for loles in i[2:]:
                        # se ha alguma atribuicao
                        if loles[2] == i[0][2] and loles[3] == i[0][3] and loles[4] == i[0][4]:
                            boolskip = False
                    if boolskip:
                        atual = group_by_vulns[i[0]]
                        # ver se eh tudo fora de control flow
                        for verify in atual:
                            allzero = True
                            for token in verify:
                                if token[2] != 0:
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

        for i in finalresult:
            print(i)
        return finalresult
