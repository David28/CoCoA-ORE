#Script to test the performance of the CoCoA tool
#And all the prints are not commented out
#folders to test must be on the master_dir variable (.../WebApps/ by default)
import csv
import os
import subprocess
import sys
from multiprocessing import Pool
import re
from tqdm import tqdm

master_dir = "../WebApps/"
output = "performance.csv"
flags = ["-e"] #change this to run with/witout encryption and with/without ore

def test_file(file_info):
    # Unpack file_info
    file_to_test, flags, files_dir = file_info

    result = file_to_test
    if os.path.isfile(files_dir + file_to_test):
        # Get the output of the main.py with flags -o -d
        p = subprocess.run(["python3", "main.py"] + flags + [file_to_test], capture_output=True)
        
        if p.returncode != 0:
            result = "Error"
        else:
            result = p.stdout.decode('utf-8').rstrip('\n')

        return file_to_test, result
    return file_to_test, result, None

def extract_performace_values(output):
    # print("---Lexer %s seconds ---" % (time.time() - start_time))
    search = re.compile(r"---Lexer (.+) seconds ---")
    lexer_time = float(search.search(output).group(1)) if search.search(output) else None
    #print("---Translator %s seconds ---" % (time.time() - start_time))
    search = re.compile(r"---Translator (.+) seconds ---")
    translator_time = float(search.search(output).group(1)) if search.search(output) else None
    #print("---Encryptor %s seconds ---" % (time.time() - start_time))
    search = re.compile(r"---Encryptor (.+) seconds ---")
    encryptor_time = float(search.search(output).group(1)) if search.search(output) else None
    #print("---VD %s seconds ---" % (time.time() - start_time))
    search = re.compile(r"---VD (.+) seconds ---")
    vd_time = float(search.search(output).group(1)) if search.search(output) else None
    return lexer_time, translator_time, encryptor_time, vd_time
if __name__ == "__main__":

    php_files = []
    for path, subdires, files in os.walk(master_dir):
        for file in files:
            if file.endswith(".php"):
                php_files.append(os.path.join(path, file))

    php_files = [(file, flags, master_dir) for file in php_files]
    rows = []
    rows = [["File", "Lexer Time", "Translator Time", "Encryptor Time", "VD Time"]]
    print("Testing files in: ", master_dir)


    with Pool() as pool:
        results = list(tqdm(pool.imap(test_file, php_files), total=len(php_files), desc="Testing files"))

    #get true count value
    count = 0
    # # Update rows with results
    for i, (file_to_test, result) in enumerate(results):
        results =  extract_performace_values(result)
        rows.append([file_to_test] + list(results))
        count += 1
    
    # #create a new csv with the output
    with open(output, 'w') as file:
        csv_writer = csv.writer(file)
        csv_writer.writerows(rows)
    print("Total files found: " + str(count))
   
