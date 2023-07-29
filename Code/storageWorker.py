######################################
#########Jorge Martins fc51033########
######################################
from cripto import AESCipher, encrypt  # , encrypt_aes
import re
from ds import MyValue
import secrets

flag = False


def _isVar(typestr):
    pattern = re.compile(r'VAR[0-9]+')
    return pattern.match(typestr)


def _isOP(typestr):
    pattern = re.compile(r'OP[0-9]+')
    return pattern.match(typestr)


def _isSans(tok):
    sans = re.compile(r'[a-zA-Z]*\_SANS')
    if sans.search(tok):
        return True
    return False


def _isSens(tok):
    sens = re.compile(r'[a-zA-Z]*\_SENS')
    if sens.search(tok):
        return True
    return False


class Worker(object):
    def __init__(self, ds, tokenstream, aeskey):
        self.ds = ds
        self.tokenstream = tokenstream
        self.next = 0
        self.order = [0]
        self.type = 0
        self.alg = AESCipher(aeskey)

    def store(self, depth, mykey):
        if self.next >= len(self.tokenstream):
            return
        else:
            curr = self.tokenstream[self.next]
            if _isVar(curr.type) and self.next+1 < len(self.tokenstream) and self.tokenstream[self.next+1].type == "OP0":
                key = curr
                self.next += 2
                curr = self.tokenstream[self.next]
                while curr.type != "END_ASSIGN":
                    if curr.type == "FUNC_CALL" or _isSens(curr.type) or _isSans(curr.type):
                        self.next += 1
                        dummie = self.tokenstream[self.next]
                        while dummie.type != "END_CALL":
                            if not _isOP(curr.type):
                                if flag:
                                    ###changes####
                                    currkey = encrypt(mykey, curr.type)
                                    curr.type = encrypt(currkey, curr.type)
                                    currkey = encrypt(mykey, dummie.type)
                                    dummie.type = encrypt(mykey, dummie.type)
                                    ############
                                    # curr.type = encrypt(mykey, curr.type)
                                    # dummie.type = encrypt(
                                    #     mykey, dummie.type)
                                val = MyValue(
                                    curr.lineno, depth, dummie, self.order[depth], self.type)
                                if flag:
                                    val = self.alg.encrypt(val._serialize())
                                self.ds.put(curr.type, val)
                            self.next += 1
                            dummie = self.tokenstream[self.next]
                    if not _isOP(curr.type):
                        if flag:
                            ########
                            currkey = encrypt(mykey, curr.type)
                            curr.type = encrypt(currkey, curr.type)
                            currkey = encrypt(mykey, key.type)
                            key.type = encrypt(currkey, key.type)
                            ########
                            # curr.type = encrypt(mykey, curr.type)
                            # key.type = encrypt(mykey, key.type)
                        val = MyValue(key.lineno, depth,
                                      curr, self.order[depth], self.type)
                        if flag:
                            val = self.alg.encrypt(val._serialize())
                        self.ds.put(key.type, val)
                    self.next += 1
                    curr = self.tokenstream[self.next]
            elif curr.type == "FUNC_CALL" or _isSens(curr.type) or _isSans(curr.type):
                key = curr
                self.next += 1
                curr = self.tokenstream[self.next]
                while curr.type != "END_CALL":
                    if not _isOP(curr.type):
                        if flag:
                            ########
                            currkey = encrypt(mykey, curr.type)
                            curr.type = encrypt(currkey, curr.type)
                            currkey = encrypt(mykey, key.type)
                            key.type = encrypt(currkey, key.type)
                            ########
                            # curr.type = encrypt(mykey, curr.type)
                            # key.type = encrypt(mykey, key.type)
                        val = MyValue(key.lineno, depth,
                                      curr, self.order[depth], self.type)
                        if flag:
                            val = self.alg.encrypt(val._serialize())
                        self.ds.put(key.type, val)
                    self.next += 1
                    curr = self.tokenstream[self.next]
            elif curr.type == "ELSEIF" or curr.type == "CASE":
                next = self.tokenstream[self.next+1]
                while next.type != "END_COND":
                    self.next += 1
                    next = self.tokenstream[self.next]
                self.next += 1
                aux = self.type
                self.type += 1  # TODO
                self.store(depth+1, mykey)
                self.type = aux
            elif curr.type == "IF":
                next = self.tokenstream[self.next+1]
                while next.type != "END_COND":
                    self.next += 1
                    next = self.tokenstream[self.next]
                self.next += 1
                if len(self.order) == depth+1:
                    self.order.append(0)
                else:
                    self.order[depth+1] = self.order[depth+1]+1
                aux = self.type
                self.type = 1  # TODO
                self.store(depth+1, mykey)
                self.type = aux
            elif curr.type == "ELSE":
                self.next += 1
                aux = self.type
                self.type = -1  # TODO
                self.store(depth+1, mykey)
                self.type = aux
            elif curr.type == "ENDIF" or curr.type == "ENDELSE" or curr.type == "ENDELSEIF" or curr.type == "ENDCASE":
                return
        self.next += 1
        self.store(depth, mykey)
