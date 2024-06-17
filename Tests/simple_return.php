<?php

$a = $_GET['a'];

function myTaint($a) {
  return $a;
} 


function myVuln($a) {
  echo $a;
  return $a;
}

$b = myVuln(myTaint($a));
echo $b;

?>

