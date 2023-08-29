<?php
ini_set('display_errors', 1);

$servername = "";
$username = "";
$password = "";
$database = "";

$sdn_con = mysqli_connect($servername, $username, $password, $database);
if(!$sdn_con){
	exit("connection failed: " . mysqli_connect_error());
}

$query = "SELECT * FROM checkhere";
$result = mysqli_query($sdn_con, $query);

$checkbox_values = array();
while($row = mysqli_fetch_assoc($result)) {
    $checkbox_values[$row['id']] = $row['status'];
}

if (isset($_POST['submit'])) {
	$ade= extract ($_POST);
	@$ssh = htmlentities($ssh);
	@$snmp = htmlentities($snmp);
   	@$telnet = htmlentities($telnet);
   

	if ($ssh != ''){
		mysqli_query($sdn_con, "update checkhere set status = '$ssh' where id=1");
	} else{
		mysqli_query($sdn_con, "update checkhere set status = '0' where id=1");
	}
	
	if ($snmp != ''){
		mysqli_query($sdn_con, "update checkhere set status = '$snmp' where id=2");
	}else{
		mysqli_query($sdn_con, "update checkhere set status = '0' where id=2");
	}
	
	if ($telnet != ''){
		mysqli_query($sdn_con, "update checkhere set status = '$telnet' where id=3");
	}else{
		mysqli_query($sdn_con, "update checkhere set status = '0' where id=3");
	}

	  echo "<script> alert('Update Successful. Please restart the SDN-Controller App for the rules to reflect.')</script>";
	  header("Refresh:0");
}

mysqli_close($sdn_con);


?>

<!DOCTYPE html>
<html lang="en">

<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content=
		"width=device-width, initial-scale=1.0">
	<title>SDN Admin Controller </title>
	<link rel="stylesheet" href="style.css">

</head>

<body>
	<br><br><br>
	<h1>ADMIN CONTROL PANEL</h1>
	<form action="" method="POST" id="form">
		<div>
			<label class="form_head">Access Control Manipulation</label><br><br>
		</div>
		<div class="form-control">
			<!-- Input Type Checkbox and values -->
			<label for="inp-1">
				<input type="checkbox" name="ssh" value="1" <?php if (isset($checkbox_values[1]) && $checkbox_values[1] == 1) echo "checked"; ?>>SSH</input>
			</label>
			<label for="inp-2">
				<input type="checkbox" name="snmp" value="1" <?php if (isset($checkbox_values[2]) && $checkbox_values[2] == 1) echo "checked"; ?>>SNMP</input>
			</label>
			<label for="inp-3">
				<input type="checkbox" name="telnet" value="1" <?php if (isset($checkbox_values[3]) && $checkbox_values[3] == 1) echo "checked"; ?>>TELNET</input>
			</label>
			<label for="inp-4">
		</div>
        <!-- submit the form -->
        	<div class="btn">
			<button  type="submit" name=submit> Submit </button>
		</div>
	</form>
</body>
</html>
