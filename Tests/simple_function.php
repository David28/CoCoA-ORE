<?php

function myVuln() {
    $a = $_GET['a'];
    return $a;
}

myEcho("trash", myVuln());

function myEcho($t, $str) {
    echo $str;
}

?>
