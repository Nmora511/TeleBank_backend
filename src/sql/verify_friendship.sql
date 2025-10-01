SELECT * FROM user_relationship
WHERE ((first_user_id = $1 AND second_user_id = $2) OR (first_user_id = $2 AND second_user_id = $1))
AND type = 'friends';
