# CoCoA

CoCoA is a tool capable of protecting code through encryption in a compact data structure while also  being able to perform static analysis over that encrypted code. 

This repository contains the source code for the CoCoA tool and also the source code of the web applications used in its testing.

# Installation

Download the .zip of the "Code" folder and extract it in your desired location.

# Execution

Before trying to execute the tool make sure all the dependencies listed below are installed in your system.

To execute CoCoA, open a terminal inside the Code/ folder and execute the main.py file with the file you wish to verify as parameter. Example:

> python3 main.py testfile.php

Use the flags:
    * To run encrypted use -e or --encrypt
    * To run encrypted with ORE additionally use -o or --ore

> python3 main.py -e -o testfile.php

### Dependencies
- Python3
- Pycryptodome
- Ply
- matplotlib




 
