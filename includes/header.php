<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Star Cinema</title>
    <link rel="stylesheet" href="./styles.css">
    <link rel="stylesheet"
        href="https://fonts.googleapis.com/css2?family=Montserrat:wght@300;400;500;600;700&display=swap">
</head>

<body>
    <header>
        <div class="container">
            <div class="logo">
                <a href="index.php">
                    <h1>⭐ Star Cinema</h1>
                </a>
            </div>
            <nav>
                <ul>
                    <?php
                    if (isset($_SESSION["user_id"]) && isset($_SESSION["role"])) {
                        if ($_SESSION["role"] === "manager") {
                            $nowshowing = false;
                            $bookings = false;
                            $login = false;
                            $register = false;
                            $logout = true;
                        } else if ($_SESSION["role"] === "customer") {
                            $nowshowing = true;
                            $bookings = true;
                            $login = false;
                            $register = false;
                            $logout = true;
                        }
                    } else {
                        $nowshowing = true;
                        $bookings = false;
                        $login = true;
                        $register = true;
                        $logout = false;
                    }

                    if ($nowshowing) {
                        echo '<li><a href="index.php">Now Showing</a></li>';
                    }
                    if ($bookings) {
                        echo '<li><a href="bookings.php">Bookings</a></li>';
                    }
                    if ($login) {
                        echo '<li><a href="login.php" class="btn-login">Login</a></li>';
                    }
                    if ($register) {
                        echo '<li><a href="register.php" class="btn-login">Register</a></li>';
                    }
                    if ($logout) {
                        echo '<li><a href="logout.php" class="btn-login">Logout</a></li>';
                    }
                    ?>
                </ul>
            </nav>
        </div>
    </header>