<?php
session_start();

if (isset($_SESSION["user_id"]) && isset($_SESSION["role"])) {
    if ($_SESSION["role"] === "manager") {
        header("Location: manager.php");
        exit();
    }
}

if (isset($_GET['id']) && is_numeric($_GET['id'])) {
    require_once("includes/connect-db.php");
    $movie_id = $_GET['id'];
    $stmt = $conn->prepare("SELECT * FROM movies WHERE movie_id = ?");
    $stmt->bind_param("i", $movie_id);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows > 0) {
        $movie = $result->fetch_assoc();
    } else {
        header("Location: index.php");
        exit();
    }
} else {
    header("Location: index.php");
    exit();
}

?>

<?php
require("includes/header.php");
?>
<main class="movie-details-page">
    <div class="container">
        <div class="movie-details">
            <div class="movie-poster-large">
                <img src="<?php echo htmlspecialchars($movie['poster']); ?>" alt="<?php echo htmlspecialchars($movie['title']); ?>">
            </div>
            <div class="movie-info-detailed">
                <h1><?php echo htmlspecialchars($movie['title']); ?></h1>
                <div class="movie-meta">
                    <span class="movie-rating"><?php echo htmlspecialchars($movie['rating']); ?></span>
                    <span class="movie-genre"><?php echo htmlspecialchars($movie['genre']); ?></span>
                    <span class="movie-duration"><?php echo htmlspecialchars($movie['duration']); ?> min</span>
                    <span class="movie-release"><?php echo htmlspecialchars($movie['release_year']); ?></span>
                </div>
                <div class="movie-director">
                    <strong>Director:</strong> <?php echo htmlspecialchars($movie['director']); ?>
                </div>
                <div class="movie-cast">
                    <strong>Cast:</strong> <?php echo htmlspecialchars($movie['cast']); ?>
                </div>
                <div class="movie-description">
                    <?php echo htmlspecialchars($movie['description']); ?>
                </div>
                <div class="movie-trailer">
                    <h3>Trailer</h3>
                    <iframe width="560" height="315" src="<?php echo htmlspecialchars($movie['trailer']); ?>" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
                </div>
            </div>
        </div>

        <?php
        // Get unique screening dates for the movie
        $stmt = $conn->prepare("SELECT DISTINCT(date) FROM screenings WHERE movie_id = ? AND date >= CURDATE() ORDER BY date, time");
        $stmt->bind_param("i", $movie_id);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows > 0) {
            echo '<div class="showtimes">';
            echo '<h2>Showtimes</h2>';
            echo '<div class="date-selector">';

            // Make first date active if no date is selected
            $first_row = $result->fetch_assoc();
            $date = htmlspecialchars(date("F j", strtotime($first_row['date'])));
            $selected_date = '';
            if (!isset($_GET['date'])) {
                $selected_date = $date;
                echo '<a href="movie-details.php?id=' . $movie_id . '&date=' . $date . '" class="date-btn active">' . $date . '</a>';
            } else if ($_GET['date'] == $date) {
                $selected_date = $date;
                echo '<a href="movie-details.php?id=' . $movie_id . '&date=' . $date . '" class="date-btn active">' . $date . '</a>';
            } else {
                echo '<a href="movie-details.php?id=' . $movie_id . '&date=' . $date . '" class="date-btn">' . $date . '</a>';
            }

            //check other dates
            while ($row = $result->fetch_assoc()) {
                $date = htmlspecialchars(date("F j", strtotime($row['date'])));
                if (!isset($_GET['date'])) {
                    echo '<a href="movie-details.php?id=' . $movie_id . '&date=' . $date . '" class="date-btn">' . $date . '</a>';
                } else if ($_GET['date'] == $date) {
                    $selected_date = $date;
                    echo '<a href="movie-details.php?id=' . $movie_id . '&date=' . $date . '" class="date-btn active">' . $date . '</a>';
                } else {
                    echo '<a href="movie-details.php?id=' . $movie_id . '&date=' . $date . '" class="date-btn">' . $date . '</a>';
                }
            }
            echo '</div>';
            echo '<div class="time-slots">';

            $stmt = $conn->prepare("SELECT * FROM screenings WHERE movie_id = ? AND date >= CURDATE() ORDER BY date, time");
            $stmt->bind_param("i", $movie_id);
            $stmt->execute();
            $result = $stmt->get_result();

            // Display showtimes for the selected date
            while ($row = $result->fetch_assoc()) {
                $screening_id = htmlspecialchars($row['screening_id']);
                $date = htmlspecialchars(date("F j", strtotime($row['date'])));
                if ($selected_date != $date) {
                    // Skip if the date does not match the selected date
                    continue;
                }
                $time = htmlspecialchars(date("g:i A", strtotime($row['time'])));
                $screen = htmlspecialchars($row['theater_id']);
                echo '<div class="time-slot ' . $date . '">';
                echo '<div class="time">' . $time . '</div>';
                echo '<div class="screen">Screen ' . $screen . '</div>';
                echo '<a href="seat-selection.php?id=' . $screening_id . '" class="btn-book-time">Book</a>';
                echo '</div>';
            }
            echo '</div>';
            echo '</div>';
        } else {
            echo '<p>No showtimes available for this movie.</p>';
        }
        ?>
    </div>
</main>

<?php
require("includes/footer.php");
?>