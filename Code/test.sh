#!/bin/bash

# Set the path to the base directory containing PHP files
base_dir="../"

# Array of directories to check
php_dirs=("Tests" "WebApps")

# Create a log file to store the runs with non-empty output
log_file="non_empty_output_runs_ore.txt"
touch "$log_file"

# Iterate through all PHP files in the specified directories and their subdirectories
for dir in "${php_dirs[@]}"; do
    php_files_dir="$base_dir$dir"
    
    find "$php_files_dir" -type f -name "*.php" | while read -r php_file; do
        # Run the Python script with the PHP file and discard the output
        python3 main.py "$php_file" > /dev/null 2>&1
        # Check output.txt and see if it's different than the string []
        output=$(cat "output.txt")
        empty="[]"
        if ! test "$output" = "$empty" ; then
            # Echo what's in the file
            cat "output.txt"
            echo ""
            # If it is not empty, append the file name to the log file
            echo "$php_file" >> "$log_file"
        fi
    done
done
