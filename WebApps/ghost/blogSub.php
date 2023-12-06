<?php

$connect = mysql_connect("localhost", "ghost", "ghost");
if(!$connect)
	{
		die ("Could Not Connect:" . mysql_error());
	}
	
mysql_select_db("ghost", $connect);

$sql = "SELECT * FROM q";

$valid = mysql_query($sql, $connect);

	while(1==1)
		{
				$data = $_GET("usenram");
				echo $data;
				
}
		

mysql_close($connect);



?>