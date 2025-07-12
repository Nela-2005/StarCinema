<?php
session_start();

if (isset($_SESSION["user_id"]) && isset($_SESSION["role"])) {
    if ($_SESSION["role"] === "customer") {
        header("Location: index.php");
        exit();
    }
} else {
    header("Location: index.php");
    exit();
}

include("includes/header.php");
require_once("includes/connect-db.php");

// Handle form submission
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $movie_id = intval($_POST['movie_id']);
    $theater_id = intval($_POST['theater_id']);
    $date = trim($_POST['date']);
    $time = trim($_POST['time']);

    $errors = [];
    if ($movie_id <= 0) $errors[] = "Movie is required.";
    if ($theater_id <= 0) $errors[] = "Theater is required.";
    if (empty($date)) $errors[] = "Date is required.";
    if (empty($time)) $errors[] = "Time is required.";

    if (empty($errors)) {
        $stmt = $conn->prepare("INSERT INTO screenings (movie_id, theater_id, date, time) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("iiss", $movie_id, $theater_id, $date, $time);
        if ($stmt->execute()) {
            header("Location: manager.php");
            exit();
        } else {
            $errors[] = "Failed to add screening: " . $stmt->error;
        }
        $stmt->close();
    }
}

// Fetch movies and theaters for dropdowns
$movies = $conn->query("SELECT movie_id, title FROM movies ORDER BY title");
$theaters = $conn->query("SELECT theater_id, theater_name FROM theaters ORDER BY theater_name");
?>

<main class="form-page">
    <div class="container">
        <h2 class="section-title">Add Screening</h2>
        <div class="form-container">
            <form action="" method="post" class="admin-form">
                <div class="form-grid">
                    <div class="form-group">
                        <label for="movie_id">Movie*</label>
                        <select id="movie_id" name="movie_id" required>
                            <option value="">Select a movie</option>
                            <?php while ($row = $movies->fetch_assoc()): ?>
                                <option value="<?php echo $row['movie_id']; ?>"><?php echo htmlspecialchars($row['title']); ?></option>
                            <?php endwhile; ?>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="theater_id">Theater*</label>
                        <select id="theater_id" name="theater_id" required>
                            <option value="">Select a theater</option>
                            <?php while ($row = $theaters->fetch_assoc()): ?>
                                <option value="<?php echo $row['theater_id']; ?>"><?php echo htmlspecialchars($row['theater_name']); ?></option>
                            <?php endwhile; ?>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="date">Date*</label>
                        <input type="date" id="date" name="date" required>
                    </div>
                    <div class="form-group">
                        <label for="time">Time*</label>
                        <input type="time" id="time" name="time" required>
                    </div>
                </div>
                <div class="form-actions">
                    <button type="submit" class="btn-primary">Add Screening</button>
                    <a href="manager.php" class="btn-secondary">Cancel</a>
                </div>
                <?php
                if (!empty($errors)) {
                    foreach ($errors as $error) {
                        echo "<p style='color: red;'>$error</p>";
                    }
                }
                ?>
            </form>
        </div>
    </div>
</main>

<?php include("includes/footer.php"); ?>