-- sqlite3 fundAPP.db // Use this command if setting up DB manually...

-- Drop existing tables if they exist
DROP TABLE IF EXISTS transactions;
DROP TABLE IF EXISTS users;

-- Create the users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    balance REAL DEFAULT 100
);

-- Create the transactions table
CREATE TABLE transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    sender_name TEXT NOT NULL,
    receiver_id INTEGER NOT NULL,
    receiver_name TEXT NOT NULL,
    amount REAL NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users (id),
    FOREIGN KEY (receiver_id) REFERENCES users (id)
);

-- Insert the default users
INSERT INTO users (username, email, password, role, balance) 
VALUES 
('admin', 'admin@fundAPP.com', 'admin123', 'admin', 100),
('john', 'john@fundAPP.com', 'iamjohn', 'user', 100),
('martha', 'martha@fundAPP.com', 'iammartha', 'user', 100),
('david', 'david@fundAPP.com', 'iamdavid', 'user', 100);

-- Default Transactions from 'admin' (id: 1)
INSERT INTO transactions (sender_id, sender_name, receiver_id, receiver_name, amount, timestamp)
VALUES 
(1, 'admin', 2, 'john', 25, '2024-08-16 07:58:51'),
(1, 'admin', 3, 'martha', 15, '2024-08-16 08:15:22'),
(1, 'admin', 2, 'john', 30, '2024-08-17 08:30:45'),
(1, 'admin', 3, 'martha', 20, '2024-08-17 10:45:10'),
(1, 'admin', 2, 'john', 10, '2024-08-18 11:50:00');

-- Default Transactions from 'john' (id: 2)
INSERT INTO transactions (sender_id, sender_name, receiver_id, receiver_name, amount, timestamp)
VALUES 
(2, 'john', 1, 'admin', 10, '2024-08-18 12:10:30'),
(2, 'john', 3, 'martha', 35, '2024-08-18 13:22:17'),
(2, 'john', 1, 'admin', 15, '2024-08-19 14:33:45'),
(2, 'john', 3, 'martha', 20, '2024-08-19 15:44:55'),
(2, 'john', 1, 'admin', 50, '2024-08-20 16:55:00');

-- Default Transactions from 'martha' (id: 3)
INSERT INTO transactions (sender_id, sender_name, receiver_id, receiver_name, amount, timestamp)
VALUES 
(3, 'martha', 1, 'admin', 20, '2024-08-20 17:05:20'),
(3, 'martha', 2, 'john', 10, '2024-08-20 18:16:30'),
(3, 'martha', 1, 'admin', 40, '2024-08-21 19:27:40'),
(3, 'martha', 2, 'john', 25, '2024-08-21 20:38:50'),
(3, 'martha', 1, 'admin', 30, '2024-08-22 21:49:59');

-- .exit // Use this command if setting up DB manually...