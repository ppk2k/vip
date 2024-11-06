<?php
session_start();
include('includes/db.php');
include('includes/functions.php');

// Fungsi untuk memvalidasi input
function validate_input($data) {
    return htmlspecialchars(stripslashes(trim($data)));
}

// Fungsi untuk memeriksa apakah kode VIP valid
function check_vip_code($conn, $code) {
    $query = "SELECT * FROM vip_codes WHERE code = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("s", $code);
    $stmt->execute();
    $result = $stmt->get_result();
    return $result->num_rows > 0;
}

// Handle login
if (isset($_POST['login'])) {
    $username = validate_input($_POST['username']);
    $password = validate_input($_POST['password']);

    $query = "SELECT * FROM users WHERE username = ? AND password = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("ss", $username, $password);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $_SESSION['username'] = $username;
        header("Location: #home");
    } else {
        echo "Username or Password is incorrect!";
    }
}

// Handle registration
if (isset($_POST['register'])) {
    $username = validate_input($_POST['username']);
    $password = validate_input($_POST['password']);
    $email = validate_input($_POST['email']);

    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    $query = "INSERT INTO users (username, password, email) VALUES (?, ?, ?)";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("sss", $username, $hashed_password, $email);
    $stmt->execute();
    echo "Registration successful!";
}

// Handle VIP code
if (isset($_POST['vip_code'])) {
    $vip_code = validate_input($_POST['vip_code']);
    
    if (check_vip_code($conn, $vip_code)) {
        echo "VIP Code is valid!";
    } else {
        echo "Invalid VIP Code!";
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header("Location: #login");
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Website - Login & Registration</title>
</head>
<body>
    <h1>Welcome to the Website</h1>
    
    <!-- Login Section -->
    <div id="login">
        <h2>Login</h2>
        <form action="index.php" method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="submit" name="login" value="Login">
        </form>
        <a href="#register">Go to Registration</a>
    </div>
    
    <!-- Registration Section -->
    <div id="register">
        <h2>Register</h2>
        <form action="index.php" method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="email" name="email" placeholder="Email" required>
            <input type="submit" name="register" value="Register">
        </form>
        <a href="#login">Go to Login</a>
    </div>
    
    <!-- VIP Code Section -->
    <div id="vip">
        <h2>VIP Code</h2>
        <form action="index.php" method="POST">
            <input type="text" name="vip_code" placeholder="Enter VIP Code" required>
            <input type="submit" value="Submit">
        </form>
    </div>
    
    <!-- Home Page (Protected) -->
    <div id="home">
        <?php
        if (isset($_SESSION['username'])) {
            echo "<h2>Welcome to the Home Page, " . $_SESSION['username'] . "!</h2>";
            echo '<a href="index.php?logout=true">Logout</a>';
        } else {
            echo "<h2>You must log in to view this page!</h2>";
        }
        ?>
    </div>

</body>
</html>
