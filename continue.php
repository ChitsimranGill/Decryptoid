<?php 
    require_once 'login.php';
  // continue.php
  session_start();
  $username = "";

  //for preventing session fixation
  if(!isset($_SESSION['initiated']))
     {
        session_regenerate_id();
        $_SESSION['initiated'] = 1; 
     }

  // for preventing session hijacking
  // compares hash of id address and user agent and if not equal then destroys the session
  if(isset($_SESSION['username']) && $_SESSION['check']==hash('ripemd128',$_SERVER['REMOTE_ADDR'].$_SERVER['HTTP_USER_AGENT']))
   {
     $username = $_SESSION['username'];
      echo <<<_HTML

        
	<html>
		<head>
			<title> Decryptoid </title>
		</head>
		<body>
			<form method = 'post' action = 'continue.php'
			enctype = 'multipart/form-data'>
				For user<br>				
				Select a file:<br>
				<input type = 'file' name = 'userfile' size = '10'><br>
				Select ciphers:
                                <select name='ciphers1' size ="size">
                                 <option value="simple">Simple Substitution</option>
                                 <option value="double">Double Transposition</option>
                                 <option value="rc4">RC4</option>
                                </select>
                                Encrypt<input type = 'checkbox' name ='encrypt1' value="encrypt">
                                Decrypt<input type = 'checkbox' name ='decrypt1' value="decrypt"><br>	
                                Enter text:							
				<input type = 'text' name = 'enterText'><br> 
                                Select ciphers:
                                <select name='ciphers' size ="size">
                                 <option value="simple">Simple Substitution</option>
                                 <option value="double">Double Transposition</option>
                                 <option value="rc4">RC4</option>
                                </select>
                                Encrypt<input type = 'checkbox' name ='encrypt' value="encrypt">
                                Decrypt<input type = 'checkbox' name ='decrypt' value="decrypt"><br>			
				<input type = 'submit' name = 'Userupload' value = 'Upload'><br>
				
			</form>
_HTML;
     
   }
   else
   {
      destroy_session_and_data(); // destroys session
      echo "Please <a href='adduser.php'>click here</a>to log in.";
 
   }
	
   //destroys session
   function destroy_session_and_data()
   {
     $_SESSION = array();
     setcookie(session_name(),'',time()-2592000,'/');
     session_destroy();
   }

  $conn = new mysqli($hn,$un,$pw,$db);
        if ($conn->connect_error)die(fatal_error());
  		if($_FILES)
		{
			//Validate file format
			if ($_FILES['userfile']['type'] === 'text/plain')
			{
				// sanitizing file
				$data = file_get_contents($_FILES['userfile']['tmp_name']);
                                $data_temp1 = trim(preg_replace('/\s+/', ' ',$data));
                                $data_temp = preg_replace('/[^A-Za-z0-9 ]/','',$data_temp1);
				//$data_no_newlines = preg_replace("/[^A-Za-z0-9]/", "", $data_temp);
                                $data_final = mysql_entities_fix_string($conn,$data_temp);		
			}
		}
        

        if( isset($_POST['Userupload']) && (isset($_POST['ciphers'])||isset($_POST['ciphers1'])) && (isset($_POST['encrypt']) || isset($_POST['decrypt']) || isset($_POST['encrypt1']) || isset($_POST['decrypt1'])))
        {
               // for text input 
             if(isset($_POST['enterText']) && strlen($_POST['enterText'])!=0)
             {
               // simple substituion
	       if(strcmp($_POST['ciphers'],"simple")==0)
               {
		 $data_temp2 = trim(preg_replace('/\s+/', ' ',$_POST['enterText']));
                 $data_temp3 = preg_replace('/[^A-Za-z0-9 ]/','',$data_temp2);
                 $tempStr = mysql_entities_fix_string($conn,$data_temp3);
                 echo simpleSubstitutionText($tempStr);
                 $cip = 'simple substitution';
                 $stmt = $conn->prepare('INSERT INTO decryptoid(username,input,cipher) VALUES(?,?,?)'); // adding input to database
                 $stmt->bind_param('sss',$username,$tempStr,$cip);
                 $stmt->execute();
 	         $stmt->close();
               }
               // double transposition
               if(strcmp($_POST['ciphers'],"double")==0)
               {
                 $data_temp2 = trim(preg_replace('/\s+/', ' ',$_POST['enterText']));
                 $data_temp3 = preg_replace('/[^A-Za-z0-9 #@]/','',$data_temp2);
                 $tempStr = mysql_entities_fix_string($conn,$data_temp3);
                 echo doubleTransposition($tempStr);
                 $cip = 'double transposition';
                 $stmt = $conn->prepare('INSERT INTO decryptoid(username,input,cipher) VALUES(?,?,?)');// adding to database
                 $stmt->bind_param('sss',$username,$tempStr,$cip);
                 $stmt->execute();
 	         $stmt->close();
               }
               // rc4
               if(strcmp($_POST['ciphers'],"rc4")==0)
               {
                 $data_temp2 = trim(preg_replace('/\s+/', ' ',$_POST['enterText']));
                 //$data_temp3 = preg_replace('/[^A-Za-z0-9 ]/','',$data_temp2);
                 //$data_temp3 = $_POST['enterText'];
                 //$tempStr = mysql_entities_fix_string($conn,$data_temp3);
                 $chal = rc4("154abcdef",$data_temp2);
                 if(strcmp($_POST['encrypt'],"encrypt")==0 && strcmp($_POST['decrypt'],"decrypt")!=0)
                 {
                 	echo "Encrypted: $chal";  
                 }
                 if(strcmp($_POST['decrypt'],"decrypt")==0 && strcmp($_POST['encrypt'],"encrypt")!=0)
                 {
                    echo "Decrypted: $chal"; 
                 }
                 $cip = 'RC4';
                 $stmt = $conn->prepare('INSERT INTO decryptoid(username,input,cipher) VALUES(?,?,?)');
                 $stmt->bind_param('sss',$username,$data_temp2,$cip);
                 $stmt->execute();
 	         $stmt->close();
                 
               }
               
             }
             // for file input
             if($_FILES && strlen($data_final)!=0)
             {
               if(strcmp($_POST['ciphers1'],"simple")==0)
               {
                 echo simpleSubstitutionFile($data_final);
                 $cip = 'simple substitution';
                 $stmt = $conn->prepare('INSERT INTO decryptoid(username,input,cipher) VALUES(?,?,?)');
                 $stmt->bind_param('sss',$username,$data_final,$cip);
                 $stmt->execute();
 	         $stmt->close();
               }
               if(strcmp($_POST['ciphers1'],"double")==0)
               {
                 $data_temp1 = trim(preg_replace('/\s+/', ' ',$data));
                 $data_temp = preg_replace('/[^A-Za-z0-9 #@]/','',$data_temp1);
		//$data_no_newlines = preg_replace("/[^A-Za-z0-9]/", "", $data_temp);
                 $data_final = mysql_entities_fix_string($conn,$data_temp);
                 echo doubleTranspositionFile($data_final);
                 $cip = 'double transposition';
                 $stmt = $conn->prepare('INSERT INTO decryptoid(username,input,cipher) VALUES(?,?,?)');
                 $stmt->bind_param('sss',$username,$data_final,$cip);
                 $stmt->execute();
 	         $stmt->close();
               }
		if(strcmp($_POST['ciphers1'],"rc4")==0)
               {
                 //$data_temp1 = trim(preg_replace('/\s+/', ' ',$data));
                 //$data_temp = preg_replace('/[^A-Za-z0-9 ]/','',$data_temp1);
                 if(strcmp($_POST['encrypt1'],"encrypt")==0 && strcmp($_POST['decrypt1'],"decrypt")!=0)
                 {
                 $data_temp1 = trim(preg_replace('/\s+/', ' ',$data));
                 $data_final = $data_temp1;
                 $try = rc4File("154abcdef",$data_final);
                 echo "Encrypted File: $try";  
                 $cip = 'RC4';
                 $stmt = $conn->prepare('INSERT INTO decryptoid(username,input,cipher) VALUES(?,?,?)');
                 $stmt->bind_param('sss',$username,$data_final,$cip);
                 $stmt->execute();
 	         $stmt->close();
                 }
                 if(strcmp($_POST['decrypt1'],"decrypt")==0 && strcmp($_POST['encrypt1'],"encrypt")!=0)
                 {
                 $data_final = trim(preg_replace('/\s+/', ' ',$data));
                 $try = rc4File("154abcdef",$data_final);
                 echo "Decrypted File: $try";
                 $cip = 'RC4';
                 $stmt = $conn->prepare('INSERT INTO decryptoid(username,input,cipher) VALUES(?,?,?)');
                 $stmt->bind_param('sss',$username,$data_final,$cip);
                 $stmt->execute();
 	         $stmt->close();
                 }
                 
                 
               }
		
             }
        }

        // simple substituion for test input
        function simpleSubstitutionText($userText)
        {
          $alphabet = str_split("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmonpqrstuvwxyz0123456789");
          $shifted = str_split("MNOPQRSTUVWXYZABCDEFGHIJKLmnopqrstuvwxyzabcdefghijkl3456127890");
          $myarray =array();
          $temparray = array(); 
          for($i = 0; $i<62; $i++)
          {
            $temparray = array($alphabet[$i],$shifted[$i]); 
            $myarray[$i] = $temparray;  
          }
          if(strcmp($_POST['encrypt'],"encrypt")==0 && strcmp($_POST['decrypt'],"decrypt")!=0)
          {
          $strToChange = str_split($userText);
          $strToPrint = "";
          for($j=0; $j<strlen($userText);$j++)
          {
        
            for($k = 0; $k<62; $k++)
            {
              if(strcmp($strToChange[$j],$myarray[$k][0])==0)
               {
                  $strToPrint.=$myarray[$k][1];
               }
              if(strcmp($strToChange[$j]," ")==0)
              {
                 $strToPrint.=" ";
              }
            }
           
           }
           return "Encrypted: $strToPrint"."<br>";
           }

           if(strcmp($_POST['decrypt'],"decrypt")==0 && strcmp($_POST['encrypt'],"encrypt")!=0)
          {
          $strToChange = str_split($userText);
          $strToPrint = "";
          for($j=0; $j<strlen($userText);$j++)
          {
        
            for($k = 0; $k<62; $k++)
            {
              if(strcmp($strToChange[$j],$myarray[$k][1])==0)
               {
                  $strToPrint.=$myarray[$k][0];
               }
              if(strcmp($strToChange[$j]," ")==0)
              {
                 $strToPrint.=" ";
              }
            }
           
           }
             return "Decrypted: $strToPrint"."<br>"; 
           }
             
        }
        
        // simple substitution for file
        function simpleSubstitutionFile($userText)
        {
          $alphabet = str_split("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmonpqrstuvwxyz0123456789");
          $shifted = str_split("MNOPQRSTUVWXYZABCDEFGHIJKLmnopqrstuvwxyzabcdefghijkl3456127890");
          $myarray =array();
          $temparray = array(); 
          for($i = 0; $i<62; $i++)
          {
            $temparray = array($alphabet[$i],$shifted[$i]); 
            $myarray[$i] = $temparray;  
          }
          if(strcmp($_POST['encrypt1'],"encrypt")==0 && strcmp($_POST['decrypt1'],"decrypt")!=0)
          {
          $strToChange = str_split($userText);
          $strToPrint = "";
          for($j=0; $j<strlen($userText);$j++)
          {
        
            for($k = 0; $k<62; $k++)
            {
              if(strcmp($strToChange[$j],$myarray[$k][0])==0)
               {
                  $strToPrint.=$myarray[$k][1];
               }
              if(strcmp($strToChange[$j]," ")==0)
              {
                 $strToPrint.=" ";
              }
            }
           
           }
           return "Encrypted File: $strToPrint"."<br>";
           }
           if(strcmp($_POST['decrypt1'],"decrypt")==0 && strcmp($_POST['encrypt1'],"encrypt")!=0)
          {
          $strToChange = str_split($userText);
          $strToPrint = "";
          for($j=0; $j<strlen($userText);$j++)
          {
        
            for($k = 0; $k<62; $k++)
            {
              if(strcmp($strToChange[$j],$myarray[$k][1])==0)
               {
                  $strToPrint.=$myarray[$k][0];
               }
              if(strcmp($strToChange[$j]," ")==0)
              {
                 $strToPrint.=" ";
              }
            }
           
           }
             return "Decrypted File: $strToPrint"."<br>"; 
           }
             
        }

         // double transposition method for text input
        function doubleTransposition($userText)
        {
         if(strcmp($_POST['encrypt'],"encrypt")==0 && strcmp($_POST['decrypt'],"decrypt")!=0)
         {
          $tempArray = str_split($userText);
          $strToPrint = "";
          $numberOfrows = (int) (strlen($userText)/4) + 1;
          $finalArray = array(); 
          $count = 0;
         // creating 2-d array of input text
         for($i = 0; $i<$numberOfrows;$i++)
          {
              
              while($count<strlen($userText))
               {
                 
                 if((($count+4)<= strlen($userText)))
                  {
                    
                    $temp = array($tempArray[$count],$tempArray[$count+1],$tempArray[$count+2],$tempArray[$count+3]);
                    $finalArray[$i] = $temp;
                    $count = $count+4;
                    break;
                    
                  }
                  elseif(($count == (strlen($userText)-1)))
                 {
                    
                    $temp1 = array($tempArray[$count],'#','#','#');
                    $finalArray[$i] = $temp1;
                    $count = $count +4;
                    break;
                    
                 }
                 elseif((($count+1) == (strlen($userText)-1)))
                 {
                   
                   $temp2 = array($tempArray[$count],$tempArray[$count+1],'#','#');
                   $finalArray[$i] = $temp2;
		   $count = $count +4;
                   break;
                   
                 }
                 elseif((($count+2) == (strlen($userText)-1)))
                {
                   
                   $temp3 = array($tempArray[$count],$tempArray[$count+1],$tempArray[$count+2],'#');
                   $finalArray[$i] = $temp3;
                   $count = $count +4;
                   break;
                   
                }
                    
               }
          }
         $temp_final_array = $finalArray;
         //swaping columns
         for($l = 0; $l<$numberOfrows; $l++)
         {
           
           $temp_final_array[$l][3] = $finalArray[$l][1];
           $temp_final_array[$l][0] = $finalArray[$l][3];
           $temp_final_array[$l][2] = $finalArray[$l][0];
           $temp_final_array[$l][1] = $finalArray[$l][2];
         }
         //getting swapped columns
         for($j = 0; $j<4; $j++)
         {
            for($h = 0; $h<$numberOfrows; $h++)
            {
               $strToPrint.=$temp_final_array[$h][$j];
            }
         }
         $tempArray = str_split($strToPrint);
         $numberOfrows = (int) (strlen($strToPrint)/3) + 1;
         $finalArray = array(); 
         $count = 0;
         //creating another 2-d array with entring input by column
         for($i = 0; $i<$numberOfrows;$i++)
          {
              
              while($count<strlen($strToPrint))
               {
                 
                 if((($count+3)<= strlen($strToPrint)))
                  {
                    
                    $temp = array($tempArray[$count],$tempArray[$count+1],$tempArray[$count+2]);
                    $finalArray[$i] = $temp;
                    $count = $count+3;
                    break;
                    
                  }
                  elseif(($count == (strlen($strToPrint)-1)))
                 {
                    
                    $temp1 = array($tempArray[$count],'@','@');
                    $finalArray[$i] = $temp1;
                    $count = $count +3;
                    break;
                    
                 }
                 elseif((($count+1) == (strlen($strToPrint)-1)))
                 {
                   
                   $temp2 = array($tempArray[$count],$tempArray[$count+1],'@');
                   $finalArray[$i] = $temp2;
		   $count = $count +3;
                   break;
                   
                 }
                    
               }
          }
       
         $temp_final_array = $finalArray;
         // swapping columns again
         for($l = 0; $l<$numberOfrows; $l++)
         {
           
           $temp_final_array[$l][0] = $finalArray[$l][2];
           $temp_final_array[$l][1] = $finalArray[$l][0];
           $temp_final_array[$l][2] = $finalArray[$l][1];
         }
         $strToPrint = "";   
         for($j = 0; $j<3; $j++)
         {
            for($h = 0; $h<$numberOfrows; $h++)
            {
               $strToPrint.=$temp_final_array[$h][$j];
            }
         }
         
         return "Encrypted: $strToPrint"."<br>";
        }
         // repeats the swapping done in encryption in reverse order
        if(strcmp($_POST['decrypt'],"decrypt")==0 && strcmp($_POST['encrypt'],"encrypt")!=0)
        {
          $tempArray = str_split($userText);
          $numberOfrows = (int) (strlen($userText)/3);
          $finalArray = array(); 
          $count = 0;
         
         for($i = 0; $i<$numberOfrows;$i++)
          {
         
             $temp = array($tempArray[$count],$tempArray[$count+$numberOfrows],$tempArray[$count+$numberOfrows+$numberOfrows]);
              $finalArray[$i] = $temp;
              $count++;
              
          }
          
       
         $temp_final_array = $finalArray;
         
         for($l = 0; $l<$numberOfrows; $l++)
         {
           
           $temp_final_array[$l][2] = $finalArray[$l][0];
           $temp_final_array[$l][0] = $finalArray[$l][1];
           $temp_final_array[$l][1] = $finalArray[$l][2];
         }

        
      
         $strToPrint = "";   
         for($j = 0; $j<$numberOfrows; $j++)
         {
            for($h = 0; $h<3; $h++)
            {
               $strToPrint.=$temp_final_array[$j][$h];
            }
         }
        
     
        $tempArray = str_split($strToPrint);
          $numberOfrows = (int) (strlen($strToPrint)/4);
          $finalArray = array(); 
          $count = 0;
         for($i = 0; $i<$numberOfrows;$i++)
          {

               $temp = array($tempArray[$count],$tempArray[$count+$numberOfrows],$tempArray[$count+$numberOfrows+$numberOfrows],$tempArray[$count+$numberOfrows+$numberOfrows+$numberOfrows]);
               $finalArray[$i] = $temp;
              	$count++;
          }
       
         $temp_final_array = $finalArray;
         for($l = 0; $l<$numberOfrows; $l++)
         {
           
           $temp_final_array[$l][1] = $finalArray[$l][3];
           $temp_final_array[$l][3] = $finalArray[$l][0];
           $temp_final_array[$l][0] = $finalArray[$l][2];
           $temp_final_array[$l][2] = $finalArray[$l][1];
         }
         
         
         $strToPrint = "";
         for($j = 0; $j<$numberOfrows; $j++)
         {
            for($h = 0; $h<4; $h++)
            {
               if(strcmp($temp_final_array[$j][$h],"#")!=0 && strcmp($temp_final_array[$j][$h],"@")!=0)
		{
               		$strToPrint.=$temp_final_array[$j][$h];
		}
            }
         }
         return "Decrypted: $strToPrint"."<br>";
        }   
        }

         // double transposition for file input
        function doubleTranspositionFile($userText)
        {
         if(strcmp($_POST['encrypt1'],"encrypt")==0 && strcmp($_POST['decrypt1'],"decrypt")!=0)
         {
          $tempArray = str_split($userText);
          $strToPrint = "";
          $numberOfrows = (int) (strlen($userText)/4) + 1;
          $finalArray = array(); 
          $count = 0;
         for($i = 0; $i<$numberOfrows;$i++)
          {
              
              while($count<strlen($userText))
               {
                 
                 if((($count+4)<= strlen($userText)))
                  {
                    
                    $temp = array($tempArray[$count],$tempArray[$count+1],$tempArray[$count+2],$tempArray[$count+3]);
                    $finalArray[$i] = $temp;
                    $count = $count+4;
                    break;
                    
                  }
                  elseif(($count == (strlen($userText)-1)))
                 {
                    
                    $temp1 = array($tempArray[$count],'#','#','#');
                    $finalArray[$i] = $temp1;
                    $count = $count +4;
                    break;
                    
                 }
                 elseif((($count+1) == (strlen($userText)-1)))
                 {
                   
                   $temp2 = array($tempArray[$count],$tempArray[$count+1],'#','#');
                   $finalArray[$i] = $temp2;
		   $count = $count +4;
                   break;
                   
                 }
                 elseif((($count+2) == (strlen($userText)-1)))
                {
                   
                   $temp3 = array($tempArray[$count],$tempArray[$count+1],$tempArray[$count+2],'#');
                   $finalArray[$i] = $temp3;
                   $count = $count +4;
                   break;
                   
                }
                    
               }
          }
         $temp_final_array = $finalArray;
         for($l = 0; $l<$numberOfrows; $l++)
         {
           
           $temp_final_array[$l][3] = $finalArray[$l][1];
           $temp_final_array[$l][0] = $finalArray[$l][3];
           $temp_final_array[$l][2] = $finalArray[$l][0];
           $temp_final_array[$l][1] = $finalArray[$l][2];
         }
         for($j = 0; $j<4; $j++)
         {
            for($h = 0; $h<$numberOfrows; $h++)
            {
               $strToPrint.=$temp_final_array[$h][$j];
            }
         }
         $tempArray = str_split($strToPrint);
         $numberOfrows = (int) (strlen($strToPrint)/3) + 1;
         $finalArray = array(); 
         $count = 0;
         for($i = 0; $i<$numberOfrows;$i++)
          {
              
              while($count<strlen($strToPrint))
               {
                 
                 if((($count+3)<= strlen($strToPrint)))
                  {
                    
                    $temp = array($tempArray[$count],$tempArray[$count+1],$tempArray[$count+2]);
                    $finalArray[$i] = $temp;
                    $count = $count+3;
                    break;
                    
                  }
                  elseif(($count == (strlen($strToPrint)-1)))
                 {
                    
                    $temp1 = array($tempArray[$count],'@','@');
                    $finalArray[$i] = $temp1;
                    $count = $count +3;
                    break;
                    
                 }
                 elseif((($count+1) == (strlen($strToPrint)-1)))
                 {
                   
                   $temp2 = array($tempArray[$count],$tempArray[$count+1],'@');
                   $finalArray[$i] = $temp2;
		   $count = $count +3;
                   break;
                   
                 }
                    
               }
          }
       
         $temp_final_array = $finalArray;
         for($l = 0; $l<$numberOfrows; $l++)
         {
           
           $temp_final_array[$l][0] = $finalArray[$l][2];
           $temp_final_array[$l][1] = $finalArray[$l][0];
           $temp_final_array[$l][2] = $finalArray[$l][1];
         }
         $strToPrint = "";   
         for($j = 0; $j<3; $j++)
         {
            for($h = 0; $h<$numberOfrows; $h++)
            {
               $strToPrint.=$temp_final_array[$h][$j];
            }
         }
         
         return "Encrypted File: $strToPrint"."<br>";
        }

        if(strcmp($_POST['decrypt1'],"decrypt")==0 && strcmp($_POST['encrypt1'],"encrypt")!=0)
        {
          $tempArray = str_split($userText);
          $numberOfrows = (int) (strlen($userText)/3);
          $finalArray = array(); 
          $count = 0;
         
         for($i = 0; $i<$numberOfrows;$i++)
          {
         
             $temp = array($tempArray[$count],$tempArray[$count+$numberOfrows],$tempArray[$count+$numberOfrows+$numberOfrows]);
              $finalArray[$i] = $temp;
              $count++;
              
          }
          
       
         $temp_final_array = $finalArray;
         
         for($l = 0; $l<$numberOfrows; $l++)
         {
           
           $temp_final_array[$l][2] = $finalArray[$l][0];
           $temp_final_array[$l][0] = $finalArray[$l][1];
           $temp_final_array[$l][1] = $finalArray[$l][2];
         }

        
      
         $strToPrint = "";   
         for($j = 0; $j<$numberOfrows; $j++)
         {
            for($h = 0; $h<3; $h++)
            {
               $strToPrint.=$temp_final_array[$j][$h];
            }
         }
        
     
        $tempArray = str_split($strToPrint);
          $numberOfrows = (int) (strlen($strToPrint)/4);
          $finalArray = array(); 
          $count = 0;
         for($i = 0; $i<$numberOfrows;$i++)
          {

               $temp = array($tempArray[$count],$tempArray[$count+$numberOfrows],$tempArray[$count+$numberOfrows+$numberOfrows],$tempArray[$count+$numberOfrows+$numberOfrows+$numberOfrows]);
               $finalArray[$i] = $temp;
              	$count++;
          }
       
         $temp_final_array = $finalArray;
         for($l = 0; $l<$numberOfrows; $l++)
         {
           
           $temp_final_array[$l][1] = $finalArray[$l][3];
           $temp_final_array[$l][3] = $finalArray[$l][0];
           $temp_final_array[$l][0] = $finalArray[$l][2];
           $temp_final_array[$l][2] = $finalArray[$l][1];
         }
         
         
         $strToPrint = "";
         for($j = 0; $j<$numberOfrows; $j++)
         {
            for($h = 0; $h<4; $h++)
            {
               if(strcmp($temp_final_array[$j][$h],"#")!=0 && strcmp($temp_final_array[$j][$h],"@")!=0)
		{
               		$strToPrint.=$temp_final_array[$j][$h];
		}
            }
         }
         return "Decrypted File: $strToPrint"."<br>";
        }   
        }
        
        // rc4 for input test
        function rc4($key, $str) 
        {
	  $state = array();
	  for ($i = 0; $i < 256; $i++) 
          {
		$state[$i] = $i;
       	  }
	  $j = 0;
	  for ($i = 0; $i < 256; $i++) 
          {
	    $j = ($j + $state[$i] + ord($key[$i % strlen($key)])) % 256;
	    $x = $state[$i];
	    $state[$i] = $state[$j];
	    $state[$j] = $x;
	  }
	  $i = 0;
	  $j = 0;
	  $result = '';
	  for ($y = 0; $y < strlen($str); $y++) 
          {
	     $i = ($i + 1) % 256;
	     $j = ($j + $state[$i]) % 256;
	     $x = $state[$i];
	     $state[$i] = $state[$j];
	     $state[$j] = $x;
	     $result .= $str[$y] ^ chr($state[($state[$i] + $state[$j]) % 256]);
	}
	return $result;
       }


        // rc4 for file input
        function rc4File($key, $str) 
	{
	  $state = array();
	  for ($i = 0; $i < 256; $i++) 
          {
		$state[$i] = $i;
	  } 
	  $j = 0;
	  for ($i = 0; $i < 256; $i++)
          {
		$j = ($j + $state[$i] + ord($key[$i % strlen($key)])) % 256;
		$x = $state[$i];
		$state[$i] = $state[$j];
	 	$state[$j] = $x;
	  }
	  $i = 0;
	  $j = 0;
	  $result = '';
	  for ($y = 0; $y < strlen($str); $y++) 
          {
	     $i = ($i + 1) % 256;
	     $j = ($j + $state[$i]) % 256;
	     $x = $state[$i];
	     $state[$i] = $state[$j];
	     $state[$j] = $x;
	     $result .= $str[$y] ^ chr($state[($state[$i] + $state[$j]) % 256]);
	  }
	  return $result;
	}
        
        // error message method
	function fatal_error()
	{	
	  echo "Oops, something went wrong (x __ x)";
	  echo '<br>';
	}
        
        function mysql_entities_fix_string($conn,$string)
	{
	  return htmlentities(mysql_fix_string($conn,$string));
	}

	function mysql_fix_string($conn,$string)
	{
	  if(get_magic_quotes_gpc())$string= stripslashes($string);
	  return $conn->real_escape_string($string);
	}
       
?>
