#!/bin/bash

# Set the path to the base directory containing PHP files
base_dir="../"

# dirs to check
php_dirs=("Tests" "WebApps")

log_folder="logs"
log_file="cifered_ore.txt"

# get all php files
for dir in "${php_dirs[@]}"; do
    php_files_dir="$base_dir$dir"
    
    find "$php_files_dir" -type f -name "*.php" | while read -r php_file; do
        python3 main.py "$php_file" > /dev/null 2>&1

        output=$(cat "output.txt")
        empty="[]" # no path found
        if ! test "$output" = "$empty" ; then
            cat "output.txt"
            echo ""
            # found a paht register what file it was
            echo "$php_file" >> "$base_dir$log_folder/$log_file"
        fi
    done
done
