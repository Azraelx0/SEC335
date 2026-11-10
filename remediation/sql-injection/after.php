<?php
// ILLUSTRATIVE ONLY — adapt to the app's DB layer (PDO / Eloquent / mysqli).
// The fix: parameterized query. Input can never change the query structure.

$stmt = $db->prepare(
    "SELECT * FROM users WHERE email = ? AND password_hash = ?"
);
$stmt->execute([$_POST['email'], hash_lookup($_POST['password'])]);
$result = $stmt->fetchAll();

// Also: verify a password *hash* (bcrypt/argon2), never compare plaintext,
// and don't leak which half of the credential was wrong.
