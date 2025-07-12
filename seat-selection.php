<?php
session_start();
if (isset($_SESSION['user_id']) && isset($_SESSION['role'])) {
    if ($_SESSION['role'] === 'manager') {
        header("Location: manager.php");
        exit();
    }
} else {
    header("Location: login.php");
    exit();
}

if (isset($_GET['id']) && is_numeric($_GET['id'])) {
    require_once("includes/connect-db.php");
    $screening_id = intval($_GET['id']);

    $stmt = $conn->prepare("SELECT m.movie_id movie_id, title, poster, s.date date, s.time time, t.theater_id theater_id, theater_name
                                FROM movies m, screenings s, theaters t
                                WHERE m.movie_id = s.movie_id
                                AND s.theater_id = t.theater_id
                                AND s.screening_id = ?;");
    $stmt->bind_param("i", $screening_id);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows > 0) {
        $screening = $result->fetch_assoc();
    } else {
        header("Location: index.php");
        exit();
    }
} else {
    header("Location: index.php");
    exit();
}

// Handle booking submission
if (isset($_POST["submit"])) {
    if (isset($_POST['selectedSeats']) && !empty($_POST['selectedSeats'])) {
        $selectedSeats = explode(',', $_POST['selectedSeats']);
        $theater_id = $_POST['theater_id'];
        $customer_id = intval($_SESSION['user_id']);
        $screening_id = intval($_POST['screening_id']);

        require_once("includes/connect-db.php");
        $stmt = $conn->prepare("SELECT customer_id FROM customers WHERE customer_id = ?;");
        $stmt->bind_param("s", $customer_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $customer = $result->fetch_assoc();


        $stmt = $conn->prepare("INSERT INTO bookings (customer_id, screening_id) VALUES (?, ?);");
        $stmt->bind_param("ii", $customer_id, $screening_id);
        $stmt->execute();

        $stmt = $conn->prepare("SELECT booking_id FROM bookings WHERE customer_id = ? AND screening_id = ?;");
        $stmt->bind_param("ii", $customer_id, $screening_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $booking = $result->fetch_assoc();
        $booking_id = $booking['booking_id'];

        foreach ($selectedSeats as $seat) {
            $stmt = $conn->prepare("SELECT seat_id FROM seats WHERE theater_id = ? AND row_number = ? AND column_number = ?");
            $row_column = explode("-", $seat);
            $row = $row_column[0];
            $column = $row_column[1];
            $stmt->bind_param("isi", $theater_id, $row, $column);
            $stmt->execute();
            $result = $stmt->get_result();
            $seat = $result->fetch_assoc();
            $seat_id = $seat['seat_id'];

            $stmt = $conn->prepare("INSERT INTO seat_bookings (booking_id, seat_id) VALUES (?, ?);");
            $stmt->bind_param("ii", $booking_id, $seat_id);
            $stmt->execute();
        }
        header("Location: bookings.php");
        exit();
    }
}

?>

<?php
require("includes/header.php");
?>

<main class="seat-selection-page">
    <div class="container">
        <div class="booking-info">
            <div class="movie-info-compact">
                <img src="<?php echo htmlspecialchars($screening['poster']); ?>" alt="<?php echo htmlspecialchars($screening['title']); ?>" class="movie-thumbnail">
                <div>
                    <h2><?php echo htmlspecialchars($screening['title']); ?></h2>
                    <p><?php echo htmlspecialchars(date("F j", strtotime($screening['date']))); ?>
                        at <?php echo htmlspecialchars(date("g:i A", strtotime($screening['time']))); ?>
                        • <?php echo htmlspecialchars($screening['theater_name']); ?></p>
                </div>
            </div>
        </div>

        <?php
        $stmt = $conn->prepare("SELECT DISTINCT(column_number) FROM seats WHERE theater_id = ? ORDER BY column_number;");
        $stmt->bind_param("i", $screening['theater_id']);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows > 0) {
        ?>
            <div class="theater-layout">
                <div class="screen-container">
                    <div class="screen">SCREEN</div>
                </div>

                <div class="seat-map-container">
                    <div class="seat-map">
                        <div class="column-label empty-corner"></div>
                        <div class="column-labels">
                            <?php
                            while ($column = $result->fetch_assoc()) {
                                $column_number = htmlspecialchars($column['column_number']);
                                echo "<div class='column-label'>$column_number</div>";
                            }
                            echo "</div>";

                            $stmt = $conn->prepare("SELECT DISTINCT(row_number) FROM seats WHERE theater_id = ? ORDER BY row_number;");
                            $stmt->bind_param("i", $screening['theater_id']);
                            $stmt->execute();
                            $result = $stmt->get_result();

                            while ($row = $result->fetch_assoc()) {
                                $row_number = htmlspecialchars($row['row_number']);

                                echo "<div class='row-label'>$row_number</div>";
                                echo "<div class='seat-row'>";
                                $seat_stmt = $conn->prepare("SELECT seat_id, row_number, column_number FROM seats WHERE theater_id = ? AND row_number = ? ORDER BY column_number;");
                                $seat_stmt->bind_param("is", $screening['theater_id'], $row_number);
                                $seat_stmt->execute();
                                $seat_result = $seat_stmt->get_result();
                                while ($seat = $seat_result->fetch_assoc()) {

                                    $seat_id = htmlspecialchars($seat['seat_id']);
                                    $column_number = htmlspecialchars($seat['column_number']);
                                    // Check if the seat is occupied
                                    $occupied_stmt = $conn->prepare("SELECT * FROM seat_bookings WHERE seat_id = ? AND booking_id IN (SELECT booking_id FROM bookings WHERE screening_id = ?);");
                                    $occupied_stmt->bind_param("ii", $seat_id, $screening_id);
                                    $occupied_stmt->execute();
                                    $occupied_result = $occupied_stmt->get_result();
                                    if ($occupied_result->num_rows > 0) {
                                        // Seat is occupied
                                        echo "<input class='seat occupied' data-row='$row_number' data-seat='$column_number' disabled>";
                                        continue;
                                    }

                                    echo "<input class='seat' data-row='$row_number' data-seat='$column_number'>";
                                }
                                echo "</div>";
                            }
                            ?>
                        </div>
                    </div>

                    <div class="seat-legend">
                        <div class="legend-item">
                            <div class="seat-sample"></div>
                            <span>Available</span>
                        </div>
                        <div class="legend-item">
                            <div class="seat-sample selected"></div>
                            <span>Selected</span>
                        </div>
                        <div class="legend-item">
                            <div class="seat-sample occupied"></div>
                            <span>Occupied</span>
                        </div>
                    </div>
                </div>

                <div class="booking-summary">
                    <h3>Booking Summary</h3>
                    <div class="summary-details">
                        <div class="summary-row">
                            <span>Selected Seats:</span>
                            <span id="selected-seats">None</span>
                        </div>
                        <div class="summary-row">
                            <span>Total Seats:</span>
                            <span id="total-count">0</span>
                        </div>
                        <div class="summary-row total price">
                            <span>Total Price:</span>
                            <span id="total-price">$0.00</span>
                        </div>
                    </div>
                    <form action="" method="POST">
                        <input type="hidden" name="screening_id" value="<?php echo htmlspecialchars($screening_id); ?>">
                        <input type="hidden" name="theater_id" value="<?php echo htmlspecialchars($screening['theater_id']); ?>">

                        <input type="submit" name="submit" value="Book Movie" id="proceed-btn" class="btn-primary" disabled>
                    </form>
                </div>
            <?php }
            ?>
            </div>
</main>

<?php
require("includes/footer.php");
?>

<script>
    document.addEventListener('DOMContentLoaded', function() {
        const seats = document.querySelectorAll('.seat');
        const selectedSeatsSpan = document.getElementById('selected-seats');
        const totalCountSpan = document.getElementById('total-count');
        const totalPriceSpan = document.getElementById('total-price');
        const proceedBtn = document.getElementById('proceed-btn');
        const seatPrice = 10; // Change this to your seat price
        const form = document.querySelector('.booking-summary form');

        // Create hidden input for selected seats
        let hiddenInput = document.createElement('input');
        hiddenInput.type = 'hidden';
        hiddenInput.name = 'selectedSeats';
        form.appendChild(hiddenInput);

        function updateSummary() {
            const selected = document.querySelectorAll('.seat.selected');
            const selectedSeats = Array.from(selected).map(seat => {
                const row = seat.getAttribute('data-row');
                const col = seat.getAttribute('data-seat');
                return row + "-" + col;
            });
            selectedSeatsSpan.textContent = selectedSeats.length > 0 ? selectedSeats.join(', ') : 'None';
            totalCountSpan.textContent = selectedSeats.length;
            totalPriceSpan.textContent = '$' + (selectedSeats.length * seatPrice).toFixed(2);
            proceedBtn.disabled = selectedSeats.length === 0;
            hiddenInput.value = selectedSeats.join(',');
        }

        // Add click event to each seat
        seats.forEach(seat => {
            seat.addEventListener('click', function() {
                if (seat.classList.contains('occupied')) return;
                seat.classList.toggle('selected');
                updateSummary();
            });
        });
    });
</script>