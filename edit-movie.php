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

include_once("includes/connect-db.php");

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $id = intval($_POST['movie_id']);
    $title = trim($_POST['title']);
    $genre = trim($_POST['genre']);
    $duration = (int) $_POST['duration'];
    $release_year = (int) $_POST['release_year'];
    $rating = $_POST['rating'] ?? null;
    $director = trim($_POST['director']);
    $cast = trim($_POST['cast']);
    $description = trim($_POST['description']);
    $start_date = trim($_POST['start_date']);
    $trailer_url = trim($_POST['trailer_url'] ?? '');

    // Validate required fields
    $errors = [];

    if (empty($title)) {
        $errors[] = "Title is required.";
    }
    if (empty($genre)) {
        $errors[] = "Genre is required.";
    }
    if ($duration <= 0) {
        $errors[] = "Duration must be a positive number.";
    }
    if ($release_year < 1900 || $release_year > 2099) {
        $errors[] = "Invalid release year.";
    }
    if (empty($director)) {
        $errors[] = "Director is required.";
    }
    if (empty($start_date)) {
        $errors[] = "Start date is required.";
    }


    // Handle poster upload
    if (isset($_FILES['poster']) && $_FILES['poster']['error'] === UPLOAD_ERR_OK) {
        $poster_tmp = $_FILES['poster']['tmp_name'];
        $poster_name = basename($_FILES['poster']['name']);
        $upload_dir = 'img/posters/';
        $poster_path = $upload_dir . $poster_name;

        // Ensure upload directory exists
        if (!is_dir($upload_dir)) {
            mkdir($upload_dir, 0755, true);
        }

        move_uploaded_file($poster_tmp, $poster_path);
    }

    if ($trailer_url != '') {
        $v = explode('?v=', $trailer_url)[1];
        $trailer_url = 'https://www.youtube.com/embed/' . $v;
    }

    if (empty($errors)) {
        if (!empty($poster_path)) {
            // Update including poster
            $stmt = $conn->prepare("UPDATE movies SET title = ?, genre = ?, duration = ?, release_year = ?, rating = ?, director = ?, cast = ?, description = ?, trailer = ?, poster = ?, start_date = ? WHERE movie_id = ?");
            $stmt->bind_param("ssiisssssssi", $title, $genre, $duration, $release_year, $rating, $director, $cast, $description, $trailer_url, $poster_path, $start_date, $id);
        } else {
            // Update without poster
            $stmt = $conn->prepare("UPDATE movies SET title = ?, genre = ?, duration = ?, release_year = ?, rating = ?, director = ?, cast = ?, description = ?, trailer = ?, start_date = ? WHERE movie_id = ?");
            $stmt->bind_param("ssiissssssi", $title, $genre, $duration, $release_year, $rating, $director, $cast, $description, $trailer_url, $start_date, $id);
        }
        $stmt->execute();
        $stmt->close();
        header("Location: manager.php");
        exit;
    } else {
        foreach ($errors as $error) {
            echo "<p style='color: red;'>$error</p>";
        }
    }
}

if ($_SERVER["REQUEST_METHOD"] == "GET") {
    $id = trim($_GET['id']);
    $stmt = $conn->prepare("SELECT * FROM movies WHERE movie_id = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows > 0) {
        $movie = $result->fetch_assoc();
    } else {
        echo "No movie found with that ID.";
    }
    $stmt->close();
}

?>

<main class="form-page">
    <div class="container">
        <h2 class="section-title">Edit Movie</h2>
        <h3><?php echo htmlspecialchars($movie['title']); ?></h3>

        <div class="form-container">
            <form action="" method="post" class="admin-form" enctype="multipart/form-data">
                <div class="form-grid">
                    <input type="hidden" name="movie_id" value="<?php echo htmlspecialchars($movie['movie_id']); ?>">

                    <div class="form-group">
                        <label for="title">Movie Title*</label>
                        <input type="text" id="title" name="title" value="<?php echo htmlspecialchars($movie['title']); ?>" required>
                    </div>

                    <div class="form-group">
                        <label for="genre">Genre*</label>
                        <input type="text" id="genre" name="genre" value="<?php echo htmlspecialchars($movie['genre']); ?>" required>
                    </div>

                    <div class="form-group">
                        <label for="duration">Duration (minutes)*</label>
                        <input type="number" id="duration" name="duration" min="1" value="<?php echo htmlspecialchars($movie['duration']); ?>" required>
                    </div>

                    <div class="form-group">
                        <label for="release_year">Release Year*</label>
                        <input type="number" id="release_year" name="release_year" min="1900" max="2099" value="<?php echo htmlspecialchars($movie['release_year']); ?>" required>
                    </div>

                    <div class="form-group">
                        <label for="rating">Rating</label>
                        <select id="rating" name="rating">
                            <option value="G">G</option>
                            <option value="PG">PG</option>
                            <option value="PG-13">PG-13</option>
                            <option value="R">R</option>
                            <option value="NC-17">NC-17</option>
                        </select>
                    </div>

                    <div class="form-group full-width">
                        <label for="director">Director*</label>
                        <input type="text" id="director" name="director" value="<?php echo htmlspecialchars($movie['director']); ?>" required>
                    </div>

                    <div class="form-group full-width">
                        <label for="cast">Cast</label>
                        <input type="text" id="cast" name="cast" placeholder="e.g. Actor 1, Actor 2, Actor 3" value="<?php echo htmlspecialchars($movie['cast']); ?>" required>
                    </div>

                    <div class="form-group full-width">
                        <label for="description">Description</label>
                        <textarea id="description" name="description" rows="5" required><?php echo htmlspecialchars($movie['description']); ?></textarea>
                    </div>

                    <div class="form-group">
                        <label for="start_date">Start Date*</label>
                        <input type="date" id="start_date" name="start_date" value="<?php echo htmlspecialchars($movie['start_date']); ?>" required>
                    </div>

                    <div class="form-group full-width">
                        <label for="trailer_url">Trailer URL (YouTube)</label>
                        <input type="url" id="trailer_url" name="trailer_url" value="<?php echo htmlspecialchars($movie['trailer']); ?>" placeholder="e.g. https://www.youtube.com/...">
                    </div>

                    <div class="form-group full-width">
                        <label for="poster">Movie Poster</label>
                        <div class="file-input-container">
                            <input type="file" id="poster" name="poster" accept="image/*">
                            <div class="file-input-preview">
                                <img id="poster-preview" src="/placeholder.svg?height=300&width=200" alt="Poster Preview">
                            </div>
                        </div>
                        <p class="input-help">Recommended size: 300x450 pixels, JPG or PNG format</p>
                    </div>
                </div>

                <div class="form-actions">
                    <button type="submit" class="btn-primary">Save Changes</button>
                    <a href="manager.php" class="btn-secondary">Cancel</a>
                </div>
            </form>
        </div>
    </div>
</main>

<script>
    // Preview uploaded poster image
    document.getElementById('poster').addEventListener('change', function(e) {
        const file = e.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = function(event) {
                document.getElementById('poster-preview').src = event.target.result;
            };
            reader.readAsDataURL(file);
        }
    });
</script>

<?php
include("includes/footer.php");
?>