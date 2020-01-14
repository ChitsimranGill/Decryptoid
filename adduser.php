<?php

// adduser.php 
require_once 'login.php';
$conn = new mysqli($hn,$un,$pw,$db);
if ($conn->connect_error)die(fatal_error());

$username = $password = $email = "";

if(isset($_POST['username']))
{
  $username = fix_string($_POST['username']);	
}
if(isset($_POST['password']))
{
  $password = fix_string($_POST['password']);	
}
if(isset($_POST['email']))
{
  $email = fix_string($_POST['email']);	
}

$fail  = validate_username($username);
$fail .= validate_password($password);
$fail .= validate_email($email);


if(isset($_POST['Login']))
{
  if(isset($_SERVER['PHP_AUTH_USER'])&& isset($_SERVER['PHP_AUTH_PW']))
  {
		$un_temp = mysql_entities_fix_string($conn,$_SERVER['PHP_AUTH_USER']);
		$pw_temp = mysql_entities_fix_string($conn,$_SERVER['PHP_AUTH_PW']);
		
		$query = "SELECT * FROM user WHERE username ='".$un_temp."'"; // table - user, query column name - username
		$result = $conn->query($query);
		if(!$result) die(fatal_error());
		elseif($result->num_rows)
		{
			$row = $result->fetch_array(MYSQLI_NUM);
			$result->close();
			$salt1 = $row[2];
			$salt2 = $row[3];
			$token = hash('ripemd128',"$salt1$pw_temp$salt2");
			if($token == $row[1])
			{
				// session
				session_start();
				$_SESSION['username'] = $un_temp;
                                $_SESSION['check'] = hash('ripemd128',$_SERVER['REMOTE_ADDR'].$_SERVER['HTTP_USER_AGENT']);
				echo "You are now logged in";
				die("<p><a href=continue.php>Click here to continue</a></p>");
			}
			else die("Invalid username/password combination");
		}
		else die("Invalid username/password combination");
  }
  else
  {
     header('WWW-Authenticate: Basic realm="Restricted Section"');
     header('HTTP/1.0 401 Unauthorized');
     die("Please enter your username and password");
  }
}

//echo "<!DOCTYPE html>\n<html><head><title>An Example Form</title>";
//echo "<p><a href=adduser.php>Signup complete, Click here to continue</a></p>";

if($fail == "")
{
  //echo "</head><body>Form data successfully validated: $username,$password,$email.</body></html>";

  //enter into data base
  // using hash
  $salts = saltCreator();
  $token1 = hash('ripemd128',$salts[0].$password.$salts[1]);
  $stmt = $conn->prepare('INSERT INTO user VALUES(?,?,?,?,?)');
  $stmt->bind_param('sssss',$username,$token1,$salts[0],$salts[1],$email);
  $stmt->execute();
  $stmt->close();
  echo "<p><a href=adduser.php>Signup complete, Click here to continue</a></p>";
  exit;
}

echo <<<_END

<style>
.signup {
  border: 1px solid #999999;
  font: normal 14px helvetica; color:#444444;
}
</style>

<script>
 function validate(form)
{
  fail = validateUsername(form.username.value)
  fail += validatePassword(form.password.value)
  fail += validateEmail(form.email.value)
  
  if(fail == "") return true
  else{ alert(fail); return false }
}  

function validateUsername(field)
{
 if(field == "") return "No Username was entered.\n"
 else if (field.length<5)
  return "Username must be at least 5 characters.\n"
 else if(/[^a-zA-Z0-9_-]/.test(field))
  return "Only a-z, A-Z, 0-9, - and _ allowed in Username.\n"
return ""
}

function validatePassword(field)
{
 if(field == "") return "No Password was entered.\n"
 else if(field.length<6)
  return "Password must be at least 6 characters.\n"
 else if (!/[a-z]/.test(field) || !/[A-Z]/.test(field) || !/[0-9]/.test(field))
  return "Passwords require one each of a-z, A-Z, and 0-9.\n"
return ""
}

function validateEmail(field)
{
 if(field == "") return "No Email was entered.\n"
 else if (!((field.indexOf(".")>0)&&
            (field.indexOf("@")>0)) ||
            /[^a-zA-Z0-9.@_-]/.test(field))
	return "The Email address is invalid.\n"
   return ""
}
</script>
</head>
<body>

<table border="0" cellpadding="2" cellspacing="5" bgcolor="#eeeeee">
  <th colspan="2" align="center">Signup Form</th>

    <tr><td colspan="2">Sorry, the following errors were found<br>
     in your form: <p><font color=red size=1><i>$fail</i></font></p>
  </td></tr>

<form method="post" action="adduser.php" onsubmit="return validate(this)">
 <tr><td>Username</td>
  <td><input type="text" maxlength="16" name="username" value="$username">
 </td></tr><tr><td>Password</td>
  <td><input type="text" maxlength="12" name="password" value="$password">
 </td></tr><tr><td>Email</td>
  <td><input type="text" maxlength="64" name="email" value="$email">
 </td></tr><tr><td colspan="2" align="center"><input type="submit" value="Signup">
 </td></tr><tr><td colspan="2" alig="centre"><input type="submit" name="Login" value="Login">
</form>
</table>
</body>
</html>

_END;



function validate_username($field)
{
  if($field == "") return "No Username was entered<br>";
  else if (strlen($field)<5)
   return "Username must be at least 5 characters<br>";
  else if(preg_match("/[^a-zA-Z0-9_-]/", $field))
   return "Only letters, numbers, - and _ in username<br>";
 return "";
}

function validate_password($field)
{
  if($field == "") return "No password was entered<br>";
  else if (strlen($field) < 6)
   return"Passwords must be at least 6 characters<br>";
  else if(!preg_match("/[a-z]/", $field) ||
          !preg_match("/[A-Z]/", $field) ||
          !preg_match("/[0-9]/", $field))
   return "Passwords require 1 each of a-z, A-Z, and 0-9<br>";
 return "";
}

function validate_email($field)
{
  if($field == "") return "No email was entered<br>";
  else if (!((strpos($field, ".")>0) &&
             (strpos($field, "@")>0)) ||
              preg_match("/[^a-zA-Z0-9.@_-]/", $field)) 
return "The email address is invalid<br>";
  return "";
}

function fix_string($string)
{
 if(get_magic_quotes_gpc()) $string = stripslashes($string);
 return htmlentities ($string);
}

function mysql_entities_fix_string($conn,$string)
{
	return htmlentities(mysql_fix_string($conn,$string));
}

function mysql_fix_string($conn,$string)
{
	if(get_magic_quotes_gpc())$string = stripslashes($string);
	return $conn->real_escape_string($string);
}

function add_user($conn,$un,$pw,$s1,$s2,$e)
{
	$stmt = $conn->prepare('INSERT INTO user VALUES(?,?,?,?,?)');
	$stmt->bind_param('sssss',$un,$pw,$s1,$s2,$e);
	$stmt->execute();
	$stmt->close();
}

function saltCreator()
{
	$salt = array("qm&h*","pg!@","hell","pink");
	$rand_index1 = mt_rand(0,3);
	$rand_index2 = mt_rand(0,3);
	return array($salt[$rand_index1], $salt[$rand_index2]);
}

function fatal_error()
{	
	echo "Oops, something went wrong (x __ x)";
	echo '<br>';
}


?>
