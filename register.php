<?php
// Session management
session_start();
if (isset($_SESSION["user_id"]) && isset($_SESSION["role"])) {
    if ($_SESSION["role"] === "manager") {
        header("Location: manager.php");
        exit();
    } else if ($_SESSION["role"] === "customer") {
        header("Location: index.php");
        exit();
    }
}
?>

<?php
// Adding customer to database
$error = "";
require_once("includes/connect-db.php");
if (isset($_POST["submit"])) {
    $name = $conn->real_escape_string($_POST["registerName"]);
    $email = $conn->real_escape_string($_POST["registerEmail"]);
    $password = $conn->real_escape_string($_POST["registerPassword"]);

    // Hash the password
    $password .= $salt;
    $hashedPassword = hash("md5", $password);

    if (!empty($name) && !empty($email) && !empty($password)) {
        // Check if email already exists
        $stmt = $conn->prepare("SELECT * FROM customers WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            $error = "Email already exists";
        } else {
            // Insert new manager into the database
            $stmt = $conn->prepare("INSERT INTO customers(customer_name, email, password) VALUES (?, ?, ?)");
            $stmt->bind_param("sss", $name, $email, $hashedPassword);
            // Check if the account was created successfully
            if ($stmt->execute()) {
                header("Location: login.php");
                exit();
            } else {
                $error = "Error creating account. Please try again.";
            }
        }
    }
}

?>
<?php
require("includes/header.php");
?>
<main class="login-page">
    <div class="container">
        <div class="auth-container">
            <div class="auth-content">
                <form id="register-form" class="auth-form active" action="" method="POST">
                    <h2>Create an Account</h2>
                    <p>Join Star Cinema to book tickets, earn rewards, and more.</p>

                    <div class="form-group">
                        <label for="register-name">Full Name</label>
                        <input type="text" id="register-name" name="registerName" required>
                    </div>

                    <div class="form-group">
                        <label for="register-email">Email</label>
                        <input type="email" id="register-email" name="registerEmail" required>
                    </div>

                    <div class="form-group">
                        <label for="register-password">Password</label>
                        <input type="password" id="register-password" name="registerPassword" required>
                    </div>

                    <?php
                    if (!empty($error)) { ?>
                        <div class="form-group">
                            <label style="color: red;"><?php echo $error; ?></label>
                        </div>
                    <?php } ?>

                    <input type="submit" name="submit" value="Create Account" class="btn-primary">

                </form>
            </div>
        </div>
    </div>
</main>

<?php
require("includes/footer.php");
?>