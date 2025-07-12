<?php
session_start();
include("includes/header.php");
if (isset($_SESSION["user_id"]) && isset($_SESSION["role"])) {
    if ($_SESSION["role"] === "manager") {
        header("Location: manager.php");
        exit();
    }
} else {
    header("Location: index.php");
    exit();
}

require_once("includes/connect-db.php");

$customer_id = $_SESSION["user_id"];

$stmt = $conn->prepare("SELECT 
    b.booking_id,
    m.title AS movie_title,
    m.poster AS poster,
    s.date AS screening_date,
    s.time AS screening_time,
    t.theater_name AS theater_name,
    GROUP_CONCAT(CONCAT(' ', seats.row_number, '-', seats.column_number) ORDER BY seats.row_number, seats.column_number) AS booked_seats
    FROM bookings b
    JOIN screenings s ON b.screening_id = s.screening_id
    JOIN movies m ON s.movie_id = m.movie_id
    JOIN theaters t ON s.theater_id = t.theater_id
    JOIN seat_bookings sb ON b.booking_id = sb.booking_id
    JOIN seats ON sb.seat_id = seats.seat_id
    WHERE b.customer_id = ?
    AND s.date >= CURDATE()
    GROUP BY b.booking_id
    ORDER BY s.date, s.time;");
$stmt->bind_param("i", $customer_id);
$stmt->execute();
$result = $stmt->get_result();

?>
<main class="seat-selection-page">
    <div class="container">
        <h2 class="section-title">My Bookings</h2>

        <?php
        if ($result->num_rows > 0) {
            echo '<div class="booking-info">';

            while ($row = $result->fetch_assoc()) {
        ?>
                <div class="movie-info-compact">
                    <img src="<?php echo htmlspecialchars($row['poster']); ?>"
                        alt="<?php echo htmlspecialchars($row['movie_title']); ?>" class="movie-thumbnail">
                    <div>
                        <h2><?php echo htmlspecialchars($row['movie_title']); ?></h2>
                        <p><?php echo htmlspecialchars(date("F j", strtotime($row['screening_date']))); ?>
                            at <?php echo htmlspecialchars(date("g:i A", strtotime($row['screening_time']))); ?>
                            • <?php echo htmlspecialchars($row['theater_name']); ?></p>
                        <p><?php echo htmlspecialchars($row['booked_seats']); ?></p>
                    </div>
                </div>
        <?php
            }

            echo '</div>';
        } else {
            echo '<p>No bookings found.</p>';
        }
        ?>
    </div>
    </section>
    <?php
    include("includes/footer.php");
    ?>