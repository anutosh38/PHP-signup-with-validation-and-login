<?php
$servername = "localhost:3306";
$username = "root";
$password = "";
$DB_NAME = "php";

// Create connection
$conn = new mysqli($servername, $username, $password,$DB_NAME);

// Check connection
if ($conn->connect_error) {
  die("Connection failed: " . $conn->connect_error);
}
echo "Connected successfully";
?>