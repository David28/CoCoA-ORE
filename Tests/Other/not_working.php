<?php
function myEcho($arg){
    echo $arg;
}

$tainted = $_GET['UserData'];
myEcho($tainted);
?>