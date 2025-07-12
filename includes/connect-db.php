<?php
$HOST = "localhost";
$USERNAME = "root";
$PASSWORD = "";
$DB = "cinema";

@$conn = new mysqli($HOST, $USERNAME, $PASSWORD, $DB);
if ($conn->connect_error) {
    exit();
}

$salt = "73nf@%nud^ksQZ";
?>