SELECT
    SUM(
        CASE
            WHEN sender_id = $1 THEN value
            WHEN receiver_id = $1 THEN -value
            ELSE 0
        END
    ) as balance
FROM transactions
WHERE ((sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1))
AND is_valid = TRUE;
