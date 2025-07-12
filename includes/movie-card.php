<div class="movie-card">
    <a href="movie-details.php?id=<?php echo htmlspecialchars($movie['movie_id']); ?>" class="movie-card-link">
        <div class="movie-poster">
            <img src="<?php echo $movie['poster'] ?>" alt="<?php echo htmlspecialchars($movie['title']); ?>">
        </div>
        <div class="movie-info">
            <h3><?php echo htmlspecialchars($movie['title']); ?></h3>
            <span class="movie-genre"><?php echo htmlspecialchars($movie['genre']); ?></span>
            <div class="movie-meta">
                <span><span class="icon-time">⏱</span> <?php echo htmlspecialchars($movie['duration']); ?> min</span>
                <?php
                if ($movie['start_date'] > $today) {
                    $start_date = date("F j", strtotime($movie['start_date']));
                    echo "<span>" . $start_date . "</span>";
                }
                ?>
            </div>
        </div>
    </a>
</div>