<?php
// register.php


header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';");


$host     = 'localhost';
$dbname   = 'thailand_grocery_db';
$username = 'root';
$password = '';

$message = '';
$error   = '';


if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $first_name = trim($_POST['first_name'] ?? '');
    $last_name  = trim($_POST['last_name'] ?? '');
    $email      = trim($_POST['email'] ?? '');
    $pass_input = $_POST['password'] ?? '';
    $address    = trim($_POST['address'] ?? '');

   
    if (empty($first_name) || empty($last_name) || empty($email) || empty($pass_input)) {
        $error = "Please fill in all required fields.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "Please enter a valid email address.";
    
    
    } elseif (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/', $pass_input)) {
        $error = "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number.";
    } else {
        try {
            $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8mb4", $username, $password, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
            ]);

            
            $checkStmt = $pdo->prepare("SELECT user_id FROM users WHERE email = ?");
            $checkStmt->execute([$email]);
            
            if ($checkStmt->fetch()) {
                $error = "Email address is already registered.";
            } else {
                
                $hashed_password = password_hash($pass_input, PASSWORD_DEFAULT);

               
                $sql = "INSERT INTO users (first_name, last_name, email, password, address) VALUES (?, ?, ?, ?, ?)";
                $stmt = $pdo->prepare($sql);
                $stmt->execute([$first_name, $last_name, $email, $hashed_password, $address]);

                $message = "Registration successful! You can now <a href='login.php'>Login here</a>.";
            }
        } catch (PDOException $e) {
            $error = "Database Error: " . $e->getMessage();
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - Thailand Grocery System</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f6f9; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .card { background: #ffffff; padding: 25px 30px; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }
        h2 { margin-top: 0; color: #333333; text-align: center; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; color: #555555; font-weight: bold; }
        input[type="text"], input[type="email"], input[type="password"], textarea { width: 100%; padding: 10px; border: 1px solid #cccccc; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background-color: #28a745; border: none; color: #ffffff; font-size: 16px; border-radius: 4px; cursor: pointer; }
        button:hover { background-color: #218838; }
        .alert { padding: 10px; margin-bottom: 15px; border-radius: 4px; }
        .alert-danger { background-color: #f8d7da; color: #721c24; }
        .alert-success { background-color: #d4edda; color: #155724; }
        .hint { font-size: 12px; color: #666; margin-top: 4px; }
        .login-link { text-align: center; margin-top: 15px; display: block; color: #007bff; text-decoration: none; }
        .login-link:hover { text-decoration: underline; }
    </style>
</head>
<body>

<div class="card">
    <h2>User Registration</h2>

    <?php if (!empty($error)): ?>
        <div class="alert alert-danger"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div>
    <?php endif; ?>

    <?php if (!empty($message)): ?>
        <div class="alert alert-success"><?= $message ?></div>
    <?php endif; ?>

    <form action="register.php" method="POST">
        <div class="form-group">
            <label for="first_name">First Name *</label>
            <input type="text" name="first_name" id="first_name" value="<?= htmlspecialchars($_POST['first_name'] ?? '', ENT_QUOTES, 'UTF-8') ?>" required>
        </div>

        <div class="form-group">
            <label for="last_name">Last Name *</label>
            <input type="text" name="last_name" id="last_name" value="<?= htmlspecialchars($_POST['last_name'] ?? '', ENT_QUOTES, 'UTF-8') ?>" required>
        </div>

        <div class="form-group">
            <label for="email">Email *</label>
            <input type="email" name="email" id="email" value="<?= htmlspecialchars($_POST['email'] ?? '', ENT_QUOTES, 'UTF-8') ?>" required>
        </div>

        <div class="form-group">
            <label for="password">Password *</label>
            <input type="password" name="password" id="password" required>
            <div class="hint">Minimum 8 characters, with uppercase, lowercase, and a number.</div>
        </div>

        <div class="form-group">
            <label for="address">Address</label>
            <textarea name="address" id="address" rows="3"><?= htmlspecialchars($_POST['address'] ?? '', ENT_QUOTES, 'UTF-8') ?></textarea>
        </div>

        <button type="submit">Register Account</button>
    </form>

    <a href="login.php" class="login-link">Already have an account? Login here</a>
</div>

</body>
</html>
