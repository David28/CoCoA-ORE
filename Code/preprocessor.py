import re
import sys
#Extract php snippets only from the code and convert explicit casts to functions
# so that they can be recognized by cocoa as sanitization functions
cast_pattern = re.compile(r'\(\s*(int|float|string|bool)\s*\)')
def preprocess_php(input_data):
    #replace all non php code with blanks
    in_php = False
    result = ""
    for line in input_data.split("\n"):
        output = line
        if re.compile(r'(<\s*\?\s*php)|(<\s*\?\s*PHP)').search(line):
            in_php = True
        if not in_php:
            output = ""
        if re.compile(r'\?\s*>').search(line):
            in_php = False
        if re.compile(r'\$\w+\s*').match(output):
            output = preprocess_casts(output)
        result += output + "\n"
    return result
var_pattern = r'(?:(?:\$\w+)|(?:[\",\']\w+[\",\'])|(?:\w+\(.+\)))'

#turn this (int) 5; into intval(5);
def convert_explicit_cast_to_function(php_code): 
    #int, float, string, bool, array, object
    pattern = r'(\((?:int|float|string|bool)\))\s*(.*)\s*;'

    if not re.compile(pattern).search(php_code):
        return php_code
    cast_pattern = r'\(\s*(int|float|string|bool)\s*\)'
    match = re.compile(pattern).search(php_code)
    new_code = re.compile(cast_pattern).sub("", match.group(0))
    cast = re.compile(cast_pattern).search(php_code).group(0)
    cast = cast.replace("(", "")
    cast = cast.replace(")", "")
    new_code = cast+"val("+new_code+")"
    new_code = new_code.replace(";", "")
    new_code += " ;"
    php_code = php_code.replace(match.group(0), new_code)
    return php_code
    
#turn $a += 0; into $a = $a +0; 
def convert_op_assign(php_code):
    whole_pattern = r'(\$\w+)(\s*[\+\-\*\/\%]\s*)(\=).*(\d+(?:\.\d+)?).*;'
    match = re.compile(whole_pattern).search(php_code)
    new_code = php_code
    if match:
        op = match.group(2)
        var = match.group(1)
        new_code = new_code.replace(op, "",1)
        new_code = new_code.replace(match.group(3), " = "+var+op+" ",1)
    return new_code


#turn $a = $a + 0; into $a = intval($a) +0;
#or $a = $a + 0.0 + $b + '5'; into $a = floatval($a) +0.0 + floatval($b+'5');
def convert_sum_cast_to_function(php_code):
    whole_pattern = r'\$\w+[\+\-\*\/\%]?\s*\=\s*(?:'+var_pattern+'.*\d+(?:\.\d+)?\s*.*\s*)|(?:\d+(?:\.\d+)?.*'+var_pattern+'\s*);'
    match = re.compile(whole_pattern).search(php_code)
    new_code = php_code
    if match:
        print(match)
        #get full match 
        #find int or float
        digit = re.compile(r'(\d+(\.\d+)?)').search(php_code).group(1)
        assign =  re.compile(r'(?:[\+\-\*\/\%]\s*)?\=\s*.*\s*;').search(php_code).group(0)
        new_assign = assign

        assign_left = re.compile(r"(?:[\+\-\*\/\%]\s*)?(\=\s*)(\s*.*\s*)"+digit).search(php_code)
        if assign_left:
            assign_left = assign_left.group(2)
            vars = re.compile(var_pattern).findall(assign_left)
            cast_type = "int" if "." not in digit else "float"
            for var in vars:
                new_assign_left = assign_left.replace(var, cast_type+"val("+var+")")
                #turn the right part of the assignment into a cast
                new_assign = new_assign.replace(assign_left, new_assign_left)            
        assign_right = re.compile(r"("+digit+r"\s*[+\-\*\/\%]\s*)(.+)(;)").search(php_code)
        if assign_right:
            assign_right = assign_right.group(2)
            new_assign_right = cast_type+"val("+assign_right+")"
            new_assign = new_assign.replace(assign_right, new_assign_right)
        new_code = new_code.replace(assign, new_assign,1)
    return new_code

def preprocess_casts(php_code):
    php_code = convert_explicit_cast_to_function(php_code)
    php_code = convert_op_assign(php_code)
    php_code = convert_sum_cast_to_function(php_code)
    return php_code

#main
if __name__ == "__main__":
    test_Case = "$a = $a + 0.0 + $b + func($c) +'5';"
    print(preprocess_casts(test_Case))
    test_Case = "$a += 0 ;"
    print(preprocess_casts(test_Case))
    test_Case = "$a = $b + (int) 5 +1;"
    print(preprocess_casts(test_Case))
    test_Case = "$a = 0 + $b + (int) 5 +1;"
    print(preprocess_casts(test_Case))
   
    


