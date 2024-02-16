<?php



$b = tainted();
echo $b;
function tainted(){
    $a = $_GET['User'];
    return $a;
}
?>