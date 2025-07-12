CREATE DATABASE cinema;

Use cinema;

CREATE TABLE movies (
    movie_id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    rating VARCHAR(5),
    duration INT NOT NULL,
    release_year INT NOT NULL,
    director VARCHAR(255) NOT NULL,
    cast VARCHAR(255),
    description TEXT,
    poster VARCHAR(255),
    trailer VARCHAR(255),
    start_date DATE NOT NULL,
    genre VARCHAR(70) NOT NULL
);

CREATE TABLE theaters (
    theater_id INT AUTO_INCREMENT PRIMARY KEY,
    theater_name VARCHAR(50) NOT NULL,
    capacity INT NOT NULL
);

CREATE TABLE screenings (
    screening_id INT AUTO_INCREMENT PRIMARY KEY,
    movie_id INT,
    theater_id INT,
    date DATE,
    time TIME,
    FOREIGN KEY (movie_id) REFERENCES movies(movie_id),
    FOREIGN KEY (theater_id) REFERENCES theaters(theater_id)
);

CREATE TABLE customers (
    customer_id INT AUTO_INCREMENT PRIMARY KEY,
    customer_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL
);

CREATE TABLE bookings (
    booking_id INT AUTO_INCREMENT PRIMARY KEY,
    screening_id INT,
    customer_id INT,
    FOREIGN KEY (screening_id) REFERENCES screenings(screening_id),
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
);

CREATE TABLE seats (
    seat_id INT AUTO_INCREMENT PRIMARY KEY,
    row_number INT NOT NULL,
    column_number INT NOT NULL,
    theater_id INT NOT NULL,
    FOREIGN KEY (theater_id) REFERENCES theaters(theater_id)
);

CREATE TABLE seat_bookings (
    booking_id INT,
    seat_id INT,
    PRIMARY KEY (booking_id, seat_id),
    FOREIGN KEY (booking_id) REFERENCES bookings(booking_id),
    FOREIGN KEY (seat_id) REFERENCES seats(seat_id)
);

CREATE TABLE managers (
    manager_id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255),
    password VARCHAR(255)
);

INSERT INTO managers(email, password) VALUES('manager@gmail.com', '627fab0331074796f4d12c640200031b');

INSERT INTO movies(title, rating, duration, release_year, director, cast, description, poster, trailer, start_date, genre) VALUES('Kill Bill', 'R', 111, 2003, 'Quentin Tarantino', 'Uma Thurman, Lucy Liu', 'A pregnant assassin, code-named The Bride, goes into a coma for four years after her ex-boss Bill brutally attacks her. When she wakes up, she sets out to seek revenge on him and his associates.', 'img/kill_bill.jpg', 'https://www.youtube.com/watch?v=7kSuas6mRpk', '2025-05-29', 'Action/Thriller');
INSERT INTO movies(title, rating, duration, release_year, director, cast, description, poster, trailer, start_date, genre) VALUES('Kill Bill: Vol 2', 'R', 137, 2004, 'Quentin Tarantino', 'Uma Thurman, Lucy Liu', 'A pregnant woman, codenamed the Bride, sets out on a journey to kill her ex-boss, Bill, and targets his brother, Budd, and Elle Driver, the only two survivors of the Deadly Vipers Assassination Squad.', 'img/kill_bill_2.jpg', 'https://www.youtube.com/watch?v=WTt8cCIvGYI', '2025-05-30', 'Action/Thriller');

INSERT INTO theaters(theater_name, capacity) VALUES('Screen 1', 60);
INSERT INTO screenings(movie_id, theater_id, date, time) VALUES(1, 1, '2025-05-29', '13:00:00');
INSERT INTO screenings(movie_id, theater_id, date, time) VALUES(1, 1, '2025-05-29', '14:00:00');
INSERT INTO screenings(movie_id, theater_id, date, time) VALUES(1, 1, '2025-05-30', '13:00:00');

INSERT INTO seats(theater_id, row_number, column_number) VALUES
(1, 1, 1), (1, 1, 2), (1, 1, 3), (1, 1, 4), (1, 1, 5), (1, 1, 6), (1, 1, 7), (1, 1, 8), (1, 1, 9), (1, 1, 10),
(1, 2, 1), (1, 2, 2), (1, 2, 3), (1, 2, 4), (1, 2, 5), (1, 2, 6), (1, 2, 7), (1, 2, 8), (1, 2, 9), (1, 2, 10),
(1, 3, 1), (1, 3, 2), (1, 3, 3), (1, 3, 4), (1, 3, 5), (1, 3, 6), (1, 3, 7), (1, 3, 8), (1, 3, 9), (1, 3, 10),
(1, 4, 1), (1, 4, 2), (1, 4, 3), (1, 4, 4), (1, 4, 5), (1, 4, 6), (1, 4, 7), (1, 4, 8), (1, 4, 9), (1, 4, 10),
(1, 5, 1), (1, 5, 2), (1, 5, 3), (1, 5, 4), (1, 5, 5), (1, 5, 6), (1, 5, 7), (1, 5, 8), (1, 5, 9), (1, 5, 10),
(1, 6, 1), (1, 6, 2), (1, 6, 3), (1, 6, 4), (1, 6, 5), (1, 6, 6), (1, 6, 7), (1, 6, 8), (1, 6, 9), (1, 6, 10),
(1, 7, 1), (1, 7, 2), (1, 7, 3), (1, 7, 4), (1, 7, 5), (1, 7, 6), (1, 7, 7), (1, 7, 8), (1, 7, 9), (1, 7, 10),
(1, 8, 1), (1, 8, 2), (1, 8, 3), (1, 8, 4), (1, 8, 5), (1, 8, 6), (1, 8, 7), (1, 8, 8), (1, 8, 9), (1, 8, 10);