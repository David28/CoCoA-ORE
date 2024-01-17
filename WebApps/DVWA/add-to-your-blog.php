<<<<<<< HEAD
<?php
	$lBlogEntry = $_REQUEST["blog_entry"];
	if(1==1){
		$query = $lBlogEntry;
		$result = mysqli_query($query);
	}
	$query2  = "SELECT * FROM blogs_table WHERE
			blogger_name like '{$lLoggedInUser}%'
			ORDER BY date DESC
			LIMIT 0 , 100";
			
	$result = mysqli_query($query2);
	    	
	$lBloggerName = $result;
	$lDate = $result;
	$lComment = $result;
	echo $lBloggerName;


?>

=======
<?php
	$lBlogEntry = $_REQUEST["blog_entry"];
	if(1==1){
		$query = $lBlogEntry;
		$result = mysqli_query($query);
	}
	$query2  = "SELECT * FROM blogs_table WHERE
			blogger_name like '{$lLoggedInUser}%'
			ORDER BY date DESC
			LIMIT 0 , 100";
			
	$result = mysqli_query($query2);
	    	
	$lBloggerName = $result;
	$lDate = $result;
	$lComment = $result;
	echo $lBloggerName;


?>

>>>>>>> ba4a299c8bbc2839742f2676de5ca1492ae8e1c0
