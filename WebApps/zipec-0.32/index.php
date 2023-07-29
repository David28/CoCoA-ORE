<?php

	
	$query = $_GET("login");
	$result = mysqli_query($query);

	$log_query = $_GET("login");
	mysqli_query($log_query);


	$result = $_GET("query");

	$page = $result;
	echo $page;
    

?>
