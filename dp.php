<?php
$host = 'hostname';  // Misalnya 'localhost' atau alamat server eksternal Anda
$username = 'db_user'; // Username database
$password = 'db_password'; // Password database
$database = 'db_name'; // Nama database yang digunakan

$conn = new mysqli($host, $username, $password, $database);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>
