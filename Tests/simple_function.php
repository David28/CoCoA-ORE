<?php

function test2(){
    return $_GET['UserData'];
}

$a = test();
$tainted = $a;

$b = "example string";
#function



$c = $b;
echo $tainted;
echo $c;

function test(){
    $in = "none";
    $in =  test2();
    return $in;
}

?>