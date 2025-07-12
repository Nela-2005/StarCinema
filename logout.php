<?php
    session_start();

    // Check tokens
    if (isset($_SESSION["user_id"]) && isset($_SESSION["role"])) {
        // Unset session variables
        unset($_SESSION["user_id"]);
        unset($_SESSION["role"]);
        // Destroy the session
        session_destroy();
    }

    // Redirect to index.php
    header("Location: index.php");
    // Clear session variables
?>