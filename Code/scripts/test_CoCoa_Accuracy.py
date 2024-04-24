#Script to test the accuracy of the CoCoA tool on the WebAppsComplete dataset
#And all the prints are not commented out
#folders to test must be on the master_dir variable (.../WebApps/ by default)
import csv
import os
import subprocess
import sys
from multiprocessing import Pool
import re

run_count = 5 #number of times to run each file
master_dir = "../Tests/WebAppsComplete/"

def test_file(file_info,flags, timeout=5):
    # Unpack file_info
    file_to_test, files_dir = file_info
    result = file_to_test
    if os.path.isfile(file_to_test):
        # Get the output of the main.py with flags -o -d
        try:
            p = subprocess.run(["python3", "main.py"] + flags+ [file_to_test], capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            result = "Timeout"
            return file_to_test, result, None
        if p.returncode != 0:
            result = "Error"
        else:
            result = p.stdout.decode('utf-8').rstrip('\n')

        return file_to_test, result
    return file_to_test, result, None


if __name__ == "__main__":

    php_files = []
    for path, subdires, files in os.walk(master_dir):
        #if "zipec" not in path:
        #    continue
        for file in files:
            if file.endswith(".php") or file.endswith(".phps"):
                php_files.append(os.path.join(path, file))
    php_files = [(file, master_dir) for file in php_files]
    rows = []
    print("Testing files in: ", master_dir)
    results = []
    count = 0
    for file in php_files:
        count += 1
        
        result = [file[0]]
        for flags in [["-p", "-o", "-d"], ["-p", "-o", "-d", "--sqli"]]:
            output = test_file(file, flags)
            classification = output[1]
            if output[1] != "Error":
                classification = "true" if "Vulnerabilitys" in output[1] else "false"
            result += [classification, output[1]]

        rows.append(result)
        print(f"Tested file {count}/{len(php_files)}: {file[0]}", end="\r")
        #clean stdout
        sys.stdout.flush()
        sys.stdout.write("\033[K")
    #group results by WebApp
    grouped = {}
    for result in rows:
        app = result[0].split("/")[3]
        if app in grouped:
            grouped[app].append(result)
        else:
            grouped[app] = [result]
    # #create a new csv with the output
    #dont use cientific notation
    # write as csv for each webapp
    for key in grouped:
        with open(f"../{key}.csv", "w") as f:
            writer = csv.writer(f)
            writer.writerows([["File", "XSS Vuln", "Output", "SQLi Vuln", "Output"]])
            writer.writerows(grouped[key])
            f.close()            
    print("Total files found: " + str(count))
   
