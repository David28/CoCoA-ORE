from tokens import MyToken
from cripto import AESCipher, encrypt  # , encrypt_aes
import re
from ds import MyValue, MyEncryptedValue
import secrets
from lib.ore_wrapper import OreVal


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
    def __init__(self, ds, tokenstream, kd_key=None, kr_key=None, ore_params=None):
        self.ds = ds
        self.tokenstream = tokenstream
        self.counter = {}    
        
        self.next = 0
        self.order = [0]
        self.type = 0
        self.ore_params = ore_params
        self.kd_key = kd_key
        self.kr_key = kr_key
        if self.ore_params:
            self.ds.put("BASE_DEPTH", OreVal(0, self.ore_params[1][0], self.ore_params[1][1]))
        else:
            self.ds.put("BASE_DEPTH", 0)

    def store(self, depth):
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
                                self.create_entry(curr, dummie, curr.lineno, depth, self.order[depth], self.type)
                            self.next += 1
                            dummie = self.tokenstream[self.next]
                    if not _isOP(curr.type):
                        self.create_entry(key,curr, key.lineno, depth, self.order[depth], self.type)
                        
                    self.next += 1
                    curr = self.tokenstream[self.next]
            elif curr.type == "FUNC_CALL" or _isSens(curr.type) or _isSans(curr.type):
                key = curr
                self.next += 1
                curr = self.tokenstream[self.next]
                while curr.type != "END_CALL":
                    if not _isOP(curr.type):
                        self.create_entry(key,curr, key.lineno, depth, self.order[depth], self.type)
                        
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
                self.store(depth+1)
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
                self.store(depth+1)
                self.type = aux
            elif curr.type == "ELSE":
                self.next += 1
                aux = self.type
                self.type = -1  # TODO
                self.store(depth+1)
                self.type = aux
            elif curr.type == "ENDIF" or curr.type == "ENDELSE" or curr.type == "ENDELSEIF" or curr.type == "ENDCASE":
                return
        self.next += 1
        self.store(depth)

    #(DET(D_Var2, 2) , RND(R_Var2, {D_Var1, R_Var1 , 4, 0,0,0})
    def create_entry(self, key_ind, val_ind, lineno, depth, order, type):
        if self.kd_key and self.kr_key:
            lineno = val_ind.lineno

            key_ind = key_ind.type
            val_ind = val_ind.type 
            self.counter[key_ind] = self.counter.get(key_ind, 0) + 1
            
            #cryptographic keys
            key_detkey = encrypt(self.kd_key, key_ind)
            key_rndkey = encrypt(self.kr_key,key_ind)
            val_detkey = encrypt(self.kd_key, val_ind)
            
            
            val_rndkey = encrypt(self.kr_key,val_ind)            

            val_ind = MyEncryptedValue(MyToken(val_detkey,lineno), val_rndkey, lineno, depth, order, type, self.ore_params)
            val_ind = AESCipher(key_rndkey).encrypt(val_ind._serialize())
            key_ind = encrypt(key_detkey, str(self.counter[key_ind]))
        else:
            val_ind = MyValue(
            key_ind.lineno, depth, MyToken(val_ind.type,val_ind.lineno), self.order[depth], self.type)
            key_ind = key_ind.type
        
        self.ds.put(key_ind, val_ind)