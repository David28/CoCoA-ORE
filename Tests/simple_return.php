<?php

function myVuln() {
  $a = $_GET['a'];
  return $a;
}

$b = myVuln();
echo $b;

?>

