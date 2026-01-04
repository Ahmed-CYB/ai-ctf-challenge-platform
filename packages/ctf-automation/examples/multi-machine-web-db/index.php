<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Employee Portal - Multi-Machine Challenge</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>🏢 Employee Management Portal</h1>
        <p class="subtitle">Multi-Machine CTF Challenge Demo</p>

        <?php
        // Database connection parameters
        $db_host = getenv('DB_HOST') ?: 'database';
        $db_user = getenv('DB_USER') ?: 'webapp_user';
        $db_pass = getenv('DB_PASSWORD') ?: 'webapp_pass123';
        $db_name = getenv('DB_NAME') ?: 'employees_db';

        // Display connection info for educational purposes
        echo "<div class='info-box'>";
        echo "<h3>🔍 System Information</h3>";
        echo "<p><strong>Database Host:</strong> $db_host</p>";
        echo "<p><strong>Database Name:</strong> $db_name</p>";
        echo "<p><strong>From Kali, access webapp at:</strong> <code>http://webapp</code></p>";
        echo "<p><strong>From Kali, access database at:</strong> <code>mysql -h database -u $db_user -p</code></p>";
        echo "</div>";

        // Intentionally vulnerable to SQL injection
        if (isset($_GET['search'])) {
            $search = $_GET['search'];
            
            echo "<div class='search-results'>";
            echo "<h3>🔎 Search Results</h3>";
            
            // Connect to database
            $conn = new mysqli($db_host, $db_user, $db_pass, $db_name);
            
            if ($conn->connect_error) {
                die("<p class='error'>Connection failed: " . $conn->connect_error . "</p>");
            }
            
            // VULNERABLE SQL QUERY - Intentionally insecure for educational purposes
            $query = "SELECT username, email, role FROM employees WHERE username LIKE '%$search%' OR email LIKE '%$search%'";
            
            echo "<p class='query-display'><strong>Query:</strong> <code>$query</code></p>";
            
            $result = $conn->query($query);
            
            if ($result) {
                if ($result->num_rows > 0) {
                    echo "<table>";
                    echo "<tr><th>Username</th><th>Email</th><th>Role</th></tr>";
                    
                    while($row = $result->fetch_assoc()) {
                        echo "<tr>";
                        echo "<td>" . htmlspecialchars($row['username']) . "</td>";
                        echo "<td>" . htmlspecialchars($row['email']) . "</td>";
                        echo "<td>" . htmlspecialchars($row['role']) . "</td>";
                        echo "</tr>";
                    }
                    
                    echo "</table>";
                } else {
                    echo "<p>No results found for: " . htmlspecialchars($search) . "</p>";
                }
            } else {
                echo "<p class='error'>Error: " . $conn->error . "</p>";
            }
            
            $conn->close();
            echo "</div>";
        }
        ?>

        <!-- Search Form -->
        <div class="search-box">
            <h3>🔍 Employee Search</h3>
            <form method="GET" action="">
                <input type="text" name="search" placeholder="Search by username or email" 
                       value="<?php echo isset($_GET['search']) ? htmlspecialchars($_GET['search']) : ''; ?>">
                <button type="submit">Search</button>
            </form>
            <p class="hint">💡 Try searching for: <code>admin</code>, <code>john</code>, or <code>@company</code></p>
        </div>

        <!-- Challenge Hints -->
        <div class="hints-box">
            <h3>📝 Challenge Objectives</h3>
            <ul>
                <li>✅ Explore the multi-machine architecture (webapp + database)</li>
                <li>✅ Find and exploit the SQL injection vulnerability</li>
                <li>✅ Access the database directly from Kali Linux</li>
                <li>✅ Enumerate database tables and columns</li>
                <li>✅ Extract the flag from the secret_data table</li>
            </ul>
            
            <h3>🔧 Tools Available in Kali</h3>
            <ul>
                <li><code>sqlmap</code> - Automated SQL injection</li>
                <li><code>mysql</code> - Direct database access</li>
                <li><code>nmap</code> - Network scanning</li>
                <li><code>curl</code> - HTTP requests</li>
            </ul>
        </div>

        <!-- Network Diagram -->
        <div class="network-diagram">
            <h3>🌐 Network Architecture</h3>
            <pre>
┌─────────────────┐
│  Kali Attacker  │
│  (attacker)     │
└────────┬────────┘
         │
    ctf-network (isolated)
         │
    ┌────┴────┐
    │         │
┌───▼──┐  ┌──▼────┐
│WebApp│  │MySQL  │
│:80   │──│:3306  │
└──────┘  └───────┘
 (webapp)  (database)

All services communicate via hostnames:
- http://webapp:80
- mysql://database:3306
            </pre>
        </div>

        <div class="footer">
            <p>🎯 This is a multi-machine CTF challenge demonstrating network isolation and service communication.</p>
            <p>🔒 Each challenge runs in its own isolated Docker network - no cross-challenge communication possible!</p>
        </div>
    </div>
</body>
</html>
