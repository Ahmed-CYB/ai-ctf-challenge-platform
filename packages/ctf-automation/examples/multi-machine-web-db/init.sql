-- Database initialization for multi-machine challenge
-- Creates tables and inserts sample data with intentional vulnerabilities

CREATE DATABASE IF NOT EXISTS employees_db;
USE employees_db;

-- Employees table
CREATE TABLE employees (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample employees (passwords are intentionally weak)
INSERT INTO employees (username, password, email, role) VALUES
('admin', 'admin123', 'admin@company.local', 'admin'),
('john.doe', 'password', 'john@company.local', 'user'),
('jane.smith', 'welcome123', 'jane@company.local', 'user'),
('bob.wilson', 'qwerty', 'bob@company.local', 'user');

-- Secret data table (contains the flag)
CREATE TABLE secret_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    data_key VARCHAR(100),
    data_value TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO secret_data (data_key, data_value) VALUES
('api_key', 'sk_live_1234567890abcdef'),
('encryption_key', 'AES256_KEY_9876543210'),
('flag', 'CTF{n3tw0rk_s3gm3nt4t10n_1s_1mp0rt4nt}');

-- Access logs table
CREATE TABLE access_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50),
    action VARCHAR(100),
    ip_address VARCHAR(45),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Grant privileges (intentionally too permissive for educational purposes)
GRANT ALL PRIVILEGES ON employees_db.* TO 'webapp_user'@'%';
FLUSH PRIVILEGES;

-- Display setup confirmation
SELECT 'Database initialized successfully' AS status;
SELECT COUNT(*) AS employee_count FROM employees;
SELECT COUNT(*) AS secret_count FROM secret_data;
