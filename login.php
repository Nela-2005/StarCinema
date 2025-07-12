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


// Authentication
$error = "";
require_once("includes/connect-db.php");
if (isset($_POST["submit"])) {
    $email = $conn->real_escape_string($_POST["loginEmail"]);
    $password = $conn->real_escape_string($_POST["loginPassword"]);

    // Hash the password
    $password .= $salt;
    $hashedPassword = hash("md5", $password);

    if (!empty($email) && !empty($password)) {
        // Check if credentials are valid and belong to a customer or manager
        $stmt = $conn->prepare("SELECT * FROM customers WHERE email = ? AND password = ?");
        $stmt->bind_param("ss", $email, $hashedPassword);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            // Fetch the user data
            $user = $result->fetch_assoc();
            $_SESSION["user_id"] = $user["customer_id"];
            $_SESSION["role"] = "customer";

            header("Location: index.php");
            exit();
        } else {
            // Check if credentials are valid and belong to a manager
            $stmt = $conn->prepare("SELECT * FROM managers WHERE email = ? AND password = ?");
            $stmt->bind_param("ss", $email, $hashedPassword);
            $stmt->execute();
            $result = $stmt->get_result();
            if ($result->num_rows > 0) {
                // Fetch the user data
                $user = $result->fetch_assoc();
                $_SESSION["user_id"] = $user["manager_id"];
                $_SESSION["role"] = "manager";

                header("Location: manager.php");
                exit();
            } else {
                $error = "Invalid email or password";
            }
        }
    }
}


include("includes/header.php");

?>

<main class="login-page">
    <div class="container">
        <div class="auth-container">
            <div class="auth-content">
                <form id="login-form" class="auth-form active" action="" method="POST">
                    <h2>Welcome Back</h2>
                    <p>Sign in to access your account and manage your bookings.</p>

                    <div class="form-group">
                        <label for="login-email">Email</label>
                        <input type="email" id="login-email" name="loginEmail" required>
                    </div>

                    <div class="form-group">
                        <label for="login-password">Password</label>
                        <input type="password" id="login-password" name="loginPassword" required>
                    </div>

                    <?php
                    if (!empty($error)) { ?>
                        <div class="form-group">
                            <label style="color: red;"><?php echo $error; ?></label>
                        </div>
                    <?php } ?>

                    <input type="submit" name="submit" value="Sign In" class="btn-primary">
                </form>
            </div>
        </div>
    </div>
</main>

<?php
require("includes/footer.php");
?>