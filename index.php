<?php
session_start();
include("includes/header.php");
if (isset($_SESSION["user_id"]) && isset($_SESSION["role"])) {
    if ($_SESSION["role"] === "manager") {
        header("Location: manager.php");
        exit();
    }
}

require_once("includes/connect-db.php");
?>
<section class="hero">
    <div class="hero-overlay"></div>
    <div class="hero-content">
        <h2>Experience Movies Like Never Before</h2>
        <p>Immerse yourself in the ultimate cinematic experience with state-of-the-art technology and premium comfort.</p>
        <?php
        if (isset($_SESSION["user_id"]) && isset($_SESSION["role"])) {
            if ($_SESSION["role"] === "customer") {
                echo '<a href="bookings.php" class="btn-primary">View Bookings</a>';
            }
        } else {
            echo '<a href="register.php" class="btn-primary">Join now</a>';
        } ?>
    </div>
</section>

<main>
    <section id="now-showing" class="now-showing">
        <div class="container">
            <h2 class="section-title">Now Showing</h2>
            <div class="movies-grid">
                <?php
                $today = date("Y-m-d");
                $now = date("H:i:s");
                $movies = $conn->execute_query("SELECT m.* FROM movies m JOIN screenings s ON m.movie_id = s.movie_id WHERE date > ? OR (date = ? AND time > ?) GROUP BY movie_id", [$today, $today, $now]);
                if ($movies->num_rows > 0) {
                    while ($movie = $movies->fetch_assoc()) {
                        include("includes/movie-card.php");
                    }
                } else {
                    echo "<p>No movies are currently showing. Please check back later!</p>";
                }
                ?>
            </div>
        </div>
    </section>

    <section id="coming-soon" class="coming-soon">
        <div class="container">
            <h2 class="section-title">Coming Soon</h2>
            <div class="movies-grid">
                <?php
                $movies = mysqli_query($conn, "SELECT m.* FROM movies m LEFT JOIN screenings s ON m.movie_id = s.movie_id WHERE s.screening_id IS NULL ORDER BY start_date");
                if ($movies->num_rows > 0) {
                    while ($movie = $movies->fetch_assoc()) {
                        include("includes/movie-card.php");
                    }
                } else {
                    echo "<p>No upcoming movies at the moment. Please check back soon!</p>";
                }
                ?>
            </div>
        </div>
    </section>

    <section class="features">
        <div class="container">
            <div class="feature">
                <div class="feature-icon">🎬</div>
                <h3>Latest Releases</h3>
                <p>Be the first to watch the newest blockbusters with our early screenings and premieres.</p>
            </div>
            <div class="feature">
                <div class="feature-icon">🍿</div>
                <h3>Concessions</h3>
                <p>Enjoy premium snacks and beverages from our extensive menu while watching your favorite movies.</p>
            </div>
            <div class="feature">
                <div class="feature-icon">🎞️</div>
                <h3>IMAX Experience</h3>
                <p>Immerse yourself in the ultimate cinematic experience with our state-of-the-art IMAX theaters.</p>
            </div>
        </div>
    </section>
</main>

<?php
require("includes/footer.php");
?>