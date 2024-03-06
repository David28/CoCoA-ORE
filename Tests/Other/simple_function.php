<?php

function fetchUserData(){
    return $_GET['UserData'];
}

function processInput($input){
    // Simulated processing, could involve validation or further manipulation
    return encodeForHTML($input);
}

function displayOutput($output){
    // Simulated display function
    echo $output;
}

$userInput = fetchUserData();
$sanitizedInput = processInput($userInput);

// Assuming $sanitizedInput is safe to display
displayOutput($sanitizedInput);

?>
