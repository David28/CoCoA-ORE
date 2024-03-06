<?php

function tainted(){
    $a = $_GET['User'];
    return $a;
}

$b = tainted();
echo $b;

?>