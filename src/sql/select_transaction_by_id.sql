SELECT * FROM transactions
WHERE id = $1
AND (sender_id = $1 OR receiver_id = $1);
