<?php

if (1==1) {
	mysql_select_db($dbtable);
	$result = $_GET("lmao");

	while ( 1==1 ) {
		$line = $result;
	}
	if (mysql_num_rows($result) == 0) {
		$okpage = "<body class='allSystemsOk'>No alerts</body>";
	}
	mysql_free_result($result);
	mysql_close();
} else {
	$okpage = "<body class='Error'>Database is unavailable</body>" ;
}
$output = $line ;

if ($okpage) {
	echo $okpage ;
	exit ;
}
echo $line;
?>

