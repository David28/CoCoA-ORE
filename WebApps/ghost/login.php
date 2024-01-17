
<?php
if ($failedloginflag==1) {
	echo '<h1><font color="#ff0000">Bad user name or password!</font></h1>';
}
echo $_SERVER['SCRIPT_NAME'];

// Begin hints section
if ($_COOKIE["showhints"]==1) {
	echo '<p><span style="background-color: #FFFF00">
	<b>For SSL Injection:</b>The old "\' or 1=1 -- " is a classic, but there are others. Check out who 
	you are logged in as after you do the injection. 
	<br><br>
	<b>For Session and Authentication:</b>As for playing with sessions, try a 
	<a href="https://addons.mozilla.org/en-US/firefox/addon/573">cookie editor</a> 
	to change your UID.
	<br><br>
	<b>For Insecure Authentication:</b>Try sniffing the traffic with Wireshark, Cain, Dsniff or Ettercap.	
	</span>'; 
}
// End hints section
?>

