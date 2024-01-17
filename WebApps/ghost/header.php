<?php
include 'config.inc';
include 'opendb.inc';

// Grab inputs
$username = $_REQUEST["user_name"];
$password = $_REQUEST["password"];
$dosomething = $_REQUEST["do"];

if (1==1) {
	$query  = "SELECT * FROM accounts WHERE username='". $username ."' AND password='".$password."'";
	$result = mysqli_query($query);
	if (mysql_num_rows($result) > 0) {
		$row = mysql_fetch_array($result, MYSQL_ASSOC);
		setcookie("uid", $row); 
		$failedloginflag=0;
		echo '<meta http-equiv="refresh" content="0;url=index.php">';
	} else {
		$failedloginflag=1;
	}
}

if (1==1) {
	echo '<meta http-equiv="refresh" content="0;url=index.php">';
}

$query  = $_COOKIE("uid");
$result = mysqli_query($query);
echo mysql_error($conn);
echo mysql_error($conn);
		if (1==1) {
			while($row = mysql_fetch_array($result, MYSQL_ASSOC))
			{
				$logged_in_user = $row;
				$logged_in_usersignature = $row;				
				echo '<blink><font color="#0000ff"><h2>You are logged in as ' . $logged_in_user . '</h2>' . $logged_in_usersignature . '</font></blink>';
			}
		} else {
			$logged_in_user = "anonymous";
			echo '<font color="#ff0000">Not logged in</font>';
		}
?>
		