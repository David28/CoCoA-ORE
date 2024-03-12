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
from lib.ore_wrapper import getInitiatedParams, OreVal
from decryptor import decrypt_lineno
from preprocessor import preprocess_php
Kd_key = "teste" #Deterministic master key
Kr_key = "teste2" #Random master key

flag = False #Flag to run encryption or not 
ore_params = None #ore depends on the flag -o
xss_sens_flag = True
decrypt_lines_flag = False
preprocess_flag = False
# Trata de tudo desde o .php até à estrutura de dados
if __name__ == '__main__':
    #get flag from command line arguments
    for arg in sys.argv[1:-1]:
        if arg == "-e" or arg == "--encrypt":
            flag = True
        elif arg == "-o" or arg == "--ore":
            flag = True
            ore_params = [getInitiatedParams() for _ in range(4)]
        elif arg == "-s" or arg == "--sqli":
            xss_sens_flag = False
        elif arg == "-d" or arg == "--decrypt":
            decrypt_lines_flag = True
        elif arg == "-p" or arg == "--preprocess":
            preprocess_flag = True
        else:
            print("Unrecognized argument: " + arg)

    if xss_sens_flag:
        input = "INPUT"
        sens = "XSS_SENS"
        sans = "XSS_SANS"
    else:
        input = "INPUT"
        sens = "SQLi_SENS"
        sans = "SQLi_SANS"
        
    
    config = yaml.safe_load(open("config.yaml"))
    # source ==> lextoken stream
    file = open(sys.argv[-1], 'r')
    filename = sys.argv[-1].split(".")[-2]
    input_data = file.read()

    start_time = time.time()
    if preprocess_flag:
        input_data = preprocess_php(input_data)
        print("---Preprocessor %s seconds ---" % (time.time() - start_time))
    start_time = time.time()
    lexer.input(input_data)

    lextokens = []
    while True:
        tok = lexer.token()
        if not tok:
            break      # No more input
        lextokens.append(tok)
        #print(tok)
    print("---Lexer %s seconds ---" % (time.time() - start_time))
    start_time = time.time()
    # lextoken stream ==> intermediate language
    intermediate = translator.translate(lextokens)
    #print(*intermediate, sep='\n')
    print("---Translator %s seconds ---" % (time.time() - start_time))
    start_time = time.time()
    # intermediate ==> data structure
    data = DataStructure()
    wrk = Worker(data, intermediate, Kd_key,Kr_key,ore_params) if flag else Worker(data,intermediate) 
    wrk.store(0)
    # print(data.data)
    print("---Encryptor %s seconds ---" % (time.time() - start_time))
    start_time = time.time()
    vd = VulnerabilityDetector(data, Kd_key)
    
    with open("output.txt", "w") as f:
        print(input,sens)
        if (flag):
            rnd_key = encrypt(Kr_key, sens)
            results = vd.detection(encrypt(Kd_key,input),encrypt(Kd_key,sens), encrypt(Kd_key,sans), rnd_key)
        else:
            results = vd.detection(input, sens, sans)
        print("---VD %s seconds ---" % (time.time() - start_time))
        
        for i in results:
            print(i)
        if decrypt_lines_flag:
            results = decrypt_lineno(results, ore_params[0],100)
        if results:
            print("Vulnerabilitys' path:")
        for i in results:
            print("* ",'->'.join(map(str,[x[1] for x in i])))
        for i in range(len(results)):
           for j in range(len(results[i])):
               results[i][j] = tuple(str(x) for x in results[i][j])
        f.write(json.dumps(results))
        f.close()
    
    #remove BASE_DEPTH from dictionary
    data.data.pop("BASE_DEPTH", None)
    
    #convert everything to bytes
    with open("filesize.txt", "wb") as f:
        pickle.dump(data.data, f)

 #wc -l

