<?php
session_start();
if (!isset($_SESSION["user_id"]) || !isset($_SESSION["role"]) || $_SESSION["role"] !== "manager") {
    header("Location: index.php");
    exit();
}

include("includes/header.php");
include_once("includes/connect-db.php");

$errors = [];
// Handle form submission
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $id = intval($_POST['screening_id']);
    $theater_id = intval($_POST['theater_id']);
    $date = trim($_POST['date']);
    $time = trim($_POST['time']);

    $errors = [];
    if ($theater_id <= 0) $errors[] = "Theater is required.";
    if (empty($date)) $errors[] = "Date is required.";
    if (empty($time)) $errors[] = "Time is required.";

    if (empty($errors)) {
        $stmt = $conn->prepare("UPDATE screenings SET theater_id = ?, date = ?, time = ? WHERE screening_id = ?");
        $stmt->bind_param("issi", $theater_id, $date, $time, $id);
        if ($stmt->execute()) {
            header("Location: manager.php");
            exit();
        } else {
            $errors[] = "Failed to update screening: " . $stmt->error;
        }
        $stmt->close();
    }
}

// Fetch screening details for editing
if ($_SERVER["REQUEST_METHOD"] == "GET" && isset($_GET['id'])) {
    $id = intval($_GET['id']);
    $stmt = $conn->prepare("SELECT * FROM screenings WHERE screening_id = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows > 0) {
        $screening = $result->fetch_assoc();
    } else {
        echo "<p>No screening found with that ID.</p>";
        include("includes/footer.php");
        exit();
    }
    $stmt->close();
}

// Fetch movie name and theaters for dropdowns
$movies = $conn->prepare("SELECT title FROM screenings, movies WHERE screenings.movie_id = movies.movie_id AND screening_id = ?");
$movies->bind_param("i", $id);
$movies->execute();
$movieResult = $movies->get_result();
$movie = $movieResult->fetch_assoc();

$theaters = $conn->query("SELECT theater_id, theater_name FROM theaters ORDER BY theater_name");
?>

<main class="form-page">
    <div class="container">
        <h2 class="section-title">Edit Screening</h2>
        <div class="form-container">
            <form action="" method="post" class="admin-form">
                <input type="hidden" name="screening_id" value="<?php echo htmlspecialchars($screening['screening_id']); ?>">
                <div class="form-grid">
                    <div class="form-group">
                        <label for="movie">Movie</label>
                        <input type="text" id="movie" name="movie" value="<?php echo htmlspecialchars($movie['title']); ?>" disabled>
                    </div>
                    <div class="form-group">
                        <label for="theater_id">Theater*</label>
                        <select id="theater_id" name="theater_id" required>
                            <option value="">Select a theater</option>
                            <?php while ($row = $theaters->fetch_assoc()): ?>
                                <option value="<?php echo $row['theater_id']; ?>" <?php if ($row['theater_id'] == $screening['theater_id']) echo 'selected'; ?>>
                                    <?php echo htmlspecialchars($row['theater_name']); ?>
                                </option>
                            <?php endwhile; ?>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="date">Date*</label>
                        <input type="date" id="date" name="date" value="<?php echo htmlspecialchars($screening['date']); ?>" required>
                    </div>
                    <div class="form-group">
                        <label for="time">Time*</label>
                        <input type="time" id="time" name="time" value="<?php echo htmlspecialchars($screening['time']); ?>" required>
                    </div>
                </div>
                <div class="form-actions">
                    <button type="submit" class="btn-primary">Save Changes</button>
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