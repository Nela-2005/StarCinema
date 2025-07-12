<?php

session_start();

if (isset($_SESSION["user_id"]) && isset($_SESSION["role"])) {
    if ($_SESSION["role"] !== "manager") {
        header("Location: index.php");
        exit();
    }
} else {
    header("Location: index.php");
    exit();
}

include("includes/connect-db.php");

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST['screening_id']) && is_numeric($_POST['screening_id'])) {
        $id = $_POST['screening_id'];

        $stmt = $conn->prepare("DELETE FROM screenings WHERE screening_id = ?");
        $stmt->bind_param("i", $id);

        if ($stmt->execute()) {
            echo "Screening deleted successfully.";
        } else {
            echo "Error deleting screening";
        }

        $stmt->close();
        header("Location: manager.php");
        exit();
    } else {
        echo "Invalid screening ID.";
    }
} else {
    echo "Invalid request method.";
}
