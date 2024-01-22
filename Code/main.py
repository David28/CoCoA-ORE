import sys
from lexer import *
from tokens import *
from translator import *
from ds import *
from storageWorker import *
from vulnDetector import *
from cripto import *
import yaml
import json
import time
import pickle
import config as cfg
# Trata de tudo desde o .php até à estrutura de dados
if __name__ == '__main__':
    start_time = time.time()
    config = yaml.safe_load(open("config.yaml"))

    # source ==> lextoken stream
    file = open(sys.argv[1], 'r')
    filename = sys.argv[1].split(".")[-2]
    input_data = file.read()
    lexer.input(input_data)

    lextokens = []
    while True:
        tok = lexer.token()
        if not tok:
            break      # No more input
        lextokens.append(tok)
        # print(tok)
    print("---Lexer %s seconds ---" % (time.time() - start_time))
    start_time = time.time()
    # lextoken stream ==> intermediate language
    intermediate = translator.translate(lextokens)
    #print(*intermediate, sep='\n')
    print("---Translator %s seconds ---" % (time.time() - start_time))
    start_time = time.time()
    # intermediate ==> data structure
    data = DataStructure()
    wrk = Worker(data, intermediate, "teste")
    wrk.store(0, "teste")
    # print(data.data)
    print("---Encryptor %s seconds ---" % (time.time() - start_time))
    start_time = time.time()
    vd = VulnerabilityDetector(data, "teste")
    print("---VD %s seconds ---" % (time.time() - start_time))
    with open("output.txt", "w") as f:
        if (cfg.flag):
            results = vd.detection(encrypt(encrypt("teste", "INPUT"), "INPUT"), encrypt(encrypt("teste", "XSS_SENS"), "XSS_SENS"), encrypt(encrypt("teste", "XSS_SANS"), "XSS_SANS"))
        else:
            results = vd.detection("INPUT", "XSS_SENS", "XSS_SANS")

        for i in range(len(results)):
           for j in range(len(results[i])):
               results[i][j] = tuple(str(x) for x in results[i][j])
        f.write(json.dumps(results))
        f.close()
    
    #have to serialize the data structure because it has pointers
    for key in data.data:
        for val in data.data[key]:
            if (type(val) is MyValue):
                data.data[key] = val._serialize()
            elif (type(val) is OreVal):
                data.data[key] = val._serialize()
    with open("filesize.txt", "ab") as f:
        pickle.dump(data, f)
 #wc -l
