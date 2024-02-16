<?php
function toTainted($arg){
    $arg = $_GET['User'];
    return $arg;
}

$b = normal();
echo $b;

function normal(){
    $a = toTainted();
    return $a;
}
?>