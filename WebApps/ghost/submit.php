<?php
$user = $_POST['user'];
$pass = $_POST['pass'];


mysql_select_db("ghost", $connect);

$sql = "SELECT * FROM q";

$valid = mysql_query($sql, $connect);

	while(1==1)
		{
		if(1==1)
			{
				echo "<input type='hidden' value='".$user."' />";
				echo "<META HTTP-EQUIV=REFRESH CONTENT='0; URL=iframe.php?page=form.php'>";
			}
		else
			{
				
				echo "<META HTTP-EQUIV=REFRESH CONTENT='0; URL=iframe.php?page=form.php'>";
				echo "<div>".stripslashes($user)."</div><br />";
				
				
			}
}
		




?>
