<?php
function myTaintedEcho(){
    $tainted = getTainted();
    echo $tainted;
}

myTaintedEcho();
$a = getTainted();
echo $a;

function getTainted(){
    $tainted = $_GET['UserData'];
    return $tainted;
}
?>