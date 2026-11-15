<?php
// edit_item.php
ini_set('display_errors', 1);
error_reporting(E_ALL);

// Ensure auth.php exists in the same folder, or this will cause a 500 Error!
require_once 'auth.php'; // Ensures session protection

// Security Header: Restricts script execution to trusted sources to mitigate XSS
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';");

$host     = 'localhost';
$dbname   = 'thailand_grocery_db';
$username = 'root';
$password = '';

$error = '';
$item_id = filter_var($_GET['id'] ?? $_POST['item_id'] ?? null, FILTER_VALIDATE_INT);

if (!$item_id) {
    header('Location: index.php');
    exit();
}

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8mb4", $username, $password, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
    ]);

    // Handle Form Update Submission
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $item_name      = trim($_POST['item_name'] ?? '');
        $unit_price_thb = filter_var($_POST['unit_price_thb'] ?? 0, FILTER_VALIDATE_FLOAT);
        $user_id        = $_SESSION['user_id']; // Current logged-in user updating the record

        if (empty($item_name)) {
            $error = "Item Name cannot be empty.";
        } elseif ($unit_price_thb === false || $unit_price_thb < 0) {
            $error = "Please enter a valid price.";
        } else {
            // Update item details and last_updated_by audit field
            $sql = "UPDATE grocery_items 
                    SET item_name = ?, unit_price_thb = ?, last_updated_by = ? 
                    WHERE item_id = ?";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$item_name, $unit_price_thb, $user_id, $item_id]);

            header('Location: index.php');
            exit();
        }
    }

    // Fetch existing item details to populate form
    $stmt = $pdo->prepare("SELECT * FROM grocery_items WHERE item_id = ?");
    $stmt->execute([$item_id]);
    $item = $stmt->fetch();

    if (!$item) {
        die("Item not found.");
    }
} catch (PDOException $e) {
    die("Database Error: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Edit Grocery Item</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f6f9; display: flex; justify-content: center; padding: 40px 0; }
        .card { background: #fff; padding: 25px 30px; border-radius: 8px; width: 100%; max-width: 400px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); }
        .form-group { margin-bottom: 15px; }
        label { display: block; font-weight: bold; margin-bottom: 5px; }
        input { width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #ffc107; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }
        .cancel-btn { display: block; text-align: center; margin-top: 10px; color: #6c757d; text-decoration: none; }
    </style>
</head>
<body>

<div class="card">
    <h2>Edit Grocery Item</h2>

    <?php if (!empty($error)): ?>
        <p style="color: red;"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></p>
    <?php endif; ?>

    <form action="edit_item.php" method="POST">
        <!-- Hidden field to pass the item_id securely when submitting -->
        <input type="hidden" name="item_id" value="<?= htmlspecialchars($item['item_id'], ENT_QUOTES, 'UTF-8') ?>">

        <div class="form-group">
            <label>Item Name</label>
            <!-- Properly completed HTML output with XSS protection -->
            <input type="text" name="item_name" value="<?= htmlspecialchars($item['item_name'], ENT_QUOTES, 'UTF-8') ?>" required>
        </div>

        <div class="form-group">
            <label>Unit Price (THB)</label>
            <!-- Input for the unit price -->
            <input type="number" step="0.01" name="unit_price_thb" value="<?= htmlspecialchars($item['unit_price_thb'], ENT_QUOTES, 'UTF-8') ?>" required>
        </div>

        <button type="submit">Update Item</button>
        <a href="index.php" class="cancel-btn">Cancel</a>
    </form>
</div>

</body>
</html>