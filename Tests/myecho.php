<?php

$tainted = $_GET['UserData'];
myecho($tainted, "heu");

function myecho($tainted, $b)
{
  echo $tainted ;
}

?>