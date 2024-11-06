<?php
// Memulai sesi PHP
session_start();

// Menyambung ke database MySQL
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "user_database"; // Pastikan database ini sudah dibuat

// Koneksi ke database
$conn = new mysqli($servername, $username, $password, $dbname);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Menangani login
if (isset($_POST['login_username'])) {
    $login_username = $_POST['login_username'];
    $login_password = $_POST['login_password'];

    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->bind_param("s", $login_username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        if (password_verify($login_password, $user['password'])) {
            $_SESSION['user'] = $user['username'];
            header("Location: home.php");
            exit();
        } else {
            echo "Incorrect password!";
        }
    } else {
        echo "No user found!";
    }
}

// Menangani registrasi
if (isset($_POST['register_username'])) {
    $register_username = $_POST['register_username'];
    $register_password = password_hash($_POST['register_password'], PASSWORD_BCRYPT);
    $register_email = $_POST['register_email'];

    $stmt = $conn->prepare("INSERT INTO users (username, password, email) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $register_username, $register_password, $register_email);
    $stmt->execute();

    echo "Registration successful!";
}

// Memverifikasi Kode VIP
if (isset($_GET['vip_code'])) {
    $vip_code = $_GET['vip_code'];

    $stmt = $conn->prepare("SELECT * FROM vip_codes WHERE code = ?");
    $stmt->bind_param("s", $vip_code);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        echo "VIP code is valid!";
    } else {
        echo "Invalid VIP code!";
    }
}

// Menangani Logout
if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header("Location: index.php");
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login and Registration</title>
</head>
<body>
    <h2>Login</h2>
    <form method="POST" action="">
        <label>Username:</label><br>
        <input type="text" name="login_username" required><br><br>
        <label>Password:</label><br>
        <input type="password" name="login_password" required><br><br>
        <input type="submit" value="Login">
    </form>

    <h2>Register</h2>
    <form method="POST" action="">
        <label>Username:</label><br>
        <input type="text" name="register_username" required><br><br>
        <label>Password:</label><br>
        <input type="password" name="register_password" required><br><br>
        <label>Email:</label><br>
        <input type="email" name="register_email" required><br><br>
        <input type="submit" value="Register">
    </form>

    <h2>Verify VIP Code</h2>
    <form method="GET" action="">
        <label>VIP Code:</label><br>
        <input type="text" name="vip_code" required><br><br>
        <input type="submit" value="Verify Code">
    </form>
</body>
</html>

<?php
// Menutup koneksi database
$conn->close();
?>
