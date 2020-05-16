<?php
session_start();
include 'connection.php';

$errors=array();
$EmailAddress='';
$PhoneNumber='';
$firstName='';
$lastName='';

// signup logic
if(isset($_POST['signup'])){

    $firstName=$_POST["fname"];
    $lastName=$_POST["lname"];
    $PhoneNumber=$_POST["phnum"];
    $Gender=$_POST["gender"];
    $EmailAddress=$_POST["email"];
    $Password=$_POST["password"];
    $ConPassword=$_POST["cpassword"];
    $birthdate=$_POST["birthday"];

        if(empty($EmailAddress)){
        $errors['email']="Email Required";
        }

        if(!filter_var($EmailAddress, FILTER_VALIDATE_EMAIL)){
         $errors['email']="Email address is invalid";   
        } 

        
        if(empty($PhoneNumber)){
            $errors['phnum']="Email Required";
        }


        if(empty($birthdate)){
            $errors['birthday']="DOB Required";
        }

    
       if(empty($firstName)){
        $errors['fname'] = "First name Required";
       }   

       if(empty($lastName)){
        $errors['lname'] = "Last name Required";
       } 

       if(empty($Password)){
        $errors['lname'] = "Password Required";
       } 

       if($Password !== $ConPassword){
        $errors['password']="The two passwords do not match";
       }


       $emailQuery="SELECT * FROM users WHERE email=? LIMIT 1"; 
       $stmnt = $conn->prepare($emailQuery); 
       $stmnt->bind_param('s',$EmailAddress);
       $stmnt->execute();
       $result = $stmnt->get_result();
       $userCount = $result->num_rows;
       $stmnt->close();
       
       if($userCount > 0){
        $errors['email']="Email already exists";
       }

    if(count($errors) === 0){
        $Password = password_hash($Password, PASSWORD_DEFAULT);
        $token = bin2hex(random_bytes(50));
        $verified = false;

    $sql = "INSERT INTO `users1` (first_name, last_name, phone_number,gender,email_id,password) 
              VALUES(?,?,?,?,?,?) "; 
      $stmnt = $conn->prepare($emailQuery); 
      $stmnt->bind_param('ssissbsss',$firstName,$lastName,$PhoneNumber,$EmailAddress,$verified,$token,$Password);
      $stmnt->execute();
      
      if ($stmnt->execute()) {
         $user_id = $conn->insert_id;
         $_SESSION['id'] = $user_id; 
         $_SESSION['firstName'] = $firstName; 
         $_SESSION['email'] = $EmailAddress; 
         $_SESSION['verified'] = $verified;     
         $_SESSION['message'] = "You are logged in!";
         $_SESSION['alert-class'] = "alert-success";
         header ('location: dashboard.php');
         exit();
      }else{
        $errors['db_error'] = "Database error: failed to register";
      }
    }

}

//login logic
if(isset($_POST['login-btn'])){

    
    $EmailAddress=$_POST["email"];
    $Password=$_POST["pass"];
    
        if(empty($EmailAddress)){
        $errors['email']="Email Required";
        }
       
        if(empty($PhoneNumber)){
            $errors['phnum']="Email Required";
        }
        
        if(empty($Password)){
            $errors['lname'] = "Password Required";
        }
        

        if(count($errors) === 0){
        $sql1 = "SELECT * FROM `users1` WHERE email_id=? OR phone_number=?";
        $stmnt = $conn->prepare($sql1); 
      $stmnt->bind_param('si',$EmailAddress,$EmailAddress);
      $stmnt->execute();
      $result = $stmnt->get_result();
      $user = $result->fetch_assoc();

      if (password_verify($Password,$user['password'])) {
        if ($stmnt->execute()) {
            
            $_SESSION['id'] = $user['id']; 
            $_SESSION['firstName'] = $user['first_name']; 
            $_SESSION['email'] = $user['email_id']; 
            $_SESSION['message'] = "You are logged in!";
            $_SESSION['alert-class'] = "alert-success";
            header ('location: dashboard.php');
            exit(); 
      }else{
          $errors['login_fail'] = "Wrong credentials";
      }

    }
      
           
    }
}


// logout
if (isset($_GET['logout'])){

    session_destroy();
    unset($_SESSION['email']);
    unset($_SESSION['id']);
    unset($_SESSION['firstName']);
    unset($_SESSION['id']);
    header('location: login.php');
    exit();
}