<?php
// ILLUSTRATIVE ONLY — replace with the real vulnerable code you find in the app source.
// The defect: user input concatenated straight into the SQL string.

$email = $_POST['email'];
$password = $_POST['password'];

$sql = "SELECT * FROM users WHERE email = '" . $email . "'
        AND password = '" . $password . "'";
$result = $db->query($sql);
// ' OR '1'='1'-- -   in $email ends the string and rewrites the WHERE clause.
