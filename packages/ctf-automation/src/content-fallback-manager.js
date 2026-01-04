/**
 * Content Fallback Manager
 * IMPROVEMENT: Enhanced fallback system with difficulty levels and better content
 */

import { generateVariationParams, randomizeFallbackContent } from './content-variation-manager.js';

/**
 * Generate fallback content based on category and difficulty
 * IMPROVEMENT: Now includes randomization for uniqueness
 */
export function getFallbackContent(category, difficulty = 'easy', scenario = {}) {
  const fallbacks = {
    web: {
      easy: () => generateBasicSQLi(scenario),
      medium: () => generateXSSChallenge(scenario),
      hard: () => generateComplexSQLi(scenario)
    },
    network: {
      easy: () => generateBasicFTP(scenario),
      medium: () => generateSMBChallenge(scenario),
      hard: () => generateSSHChallenge(scenario)
    },
    crypto: {
      easy: () => generateCaesarCipher(scenario),
      medium: () => generateVigenereCipher(scenario),
      hard: () => generateRSAChallenge(scenario)
    }
  };

  const categoryFallbacks = fallbacks[category];
  if (!categoryFallbacks) {
    throw new Error(`No fallback content available for category: ${category}`);
  }

  const difficultyFallback = categoryFallbacks[difficulty] || categoryFallbacks.easy;
  const fallbackContent = difficultyFallback();
  
  // IMPROVEMENT: Randomize fallback content for uniqueness
  const variations = generateVariationParams(category, scenario);
  return randomizeFallbackContent(fallbackContent, variations);
}

/**
 * Generate basic SQL injection challenge (Easy)
 */
function generateBasicSQLi(scenario) {
  // IMPROVEMENT: Generate unique flag with timestamp and random
  const timestamp = Date.now().toString(36).substring(0, 6);
  const random = crypto.randomBytes(4).toString('hex');
  const flag = `CTF{web_sqli_basic_${timestamp}_${random}}`;
  
  // IMPROVEMENT: Add variation to title and description
  const titles = [
    'SQL Injection Challenge',
    'Login Bypass Challenge',
    'Database Authentication Flaw',
    'SQL Injection Login Exploit',
    'Vulnerable Login Portal'
  ];
  const descriptions = [
    'A simple login form with a SQL injection vulnerability.',
    'A corporate login portal with a critical authentication flaw.',
    'An e-commerce site with a vulnerable login system.',
    'A web application with SQL injection in the authentication mechanism.',
    'A user portal with an exploitable login form.'
  ];
  
  const title = scenario.title || titles[Math.floor(Math.random() * titles.length)];
  const description = scenario.description || descriptions[Math.floor(Math.random() * descriptions.length)];

  const indexPHP = `<?php
// ${title}
// ${description}

$servername = "localhost";
$username = "root";
$password = "password";
$dbname = "ctf_db";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = $_POST['username'];
    $pass = $_POST['password'];
    
    // Vulnerable SQL query - no parameterization
    $sql = "SELECT * FROM users WHERE username = '$user' AND password = '$pass'";
    $result = $conn->query($sql);
    
    if ($result && $result->num_rows > 0) {
        $row = $result->fetch_assoc();
        echo "<h1>Welcome, " . htmlspecialchars($row['username']) . "!</h1>";
        echo "<p>Flag: " . htmlspecialchars($row['flag']) . "</p>";
    } else {
        echo "<h1>Login Failed</h1>";
        echo "<p>Invalid username or password.</p>";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Login - ${title}</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; }
        form { border: 1px solid #ddd; padding: 20px; border-radius: 5px; }
        input { width: 100%; padding: 10px; margin: 5px 0; }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h2>Login Page</h2>
    <p>${description}</p>
    <form method="POST">
        <label>Username:</label><br>
        <input type="text" name="username" required><br>
        <label>Password:</label><br>
        <input type="password" name="password" required><br><br>
        <button type="submit">Login</button>
    </form>
</body>
</html>`;

  const databaseSQL = `CREATE DATABASE IF NOT EXISTS ${dbName};
USE ${dbName};

CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50),
    password VARCHAR(50),
    flag VARCHAR(100)
);

INSERT INTO users (username, password, flag) VALUES 
('admin', 'secure_password_123', '${flag}'),
('user', 'password', 'CTF{fake_flag}'),
('test', 'test123', 'CTF{not_the_flag}');`;

  return {
    files: [
      {
        name: 'index.php',
        path: '',
        content: indexPHP
      },
      {
        name: 'database.sql',
        path: '',
        content: databaseSQL
      },
      {
        name: 'README.txt',
        path: '',
        content: `SQL Injection Challenge (Easy)

Objective:
Bypass the login form to retrieve the flag.

Hints:
1. The login form uses direct string concatenation in SQL queries
2. Try using SQL operators like OR, AND
3. Comment out the password check using SQL comments

Tools:
- Browser (for manual testing)
- Burp Suite (for intercepting requests)
- sqlmap (for automated exploitation)

Flag Format: CTF{...}`
      }
    ],
    flag: flag,
    configuration: {
      vulnerability: 'sqli',
      difficulty: 'easy',
      exploitPath: "Login form is vulnerable to SQL injection. Try: username=admin' OR '1'='1'-- with any password",
      flagLocation: 'Database table: users, column: flag (admin row)',
      tools: ['sqlmap', 'burpsuite', 'browser'],
      setup: `apt-get update && apt-get install -y mysql-server php-mysql apache2
service mysql start
mysql < /challenge/database.sql
cp /challenge/index.php /var/www/html/
service apache2 start`,
      hints: [
        'The login form uses direct string concatenation',
        'Try using SQL operators',
        'Comment out parts of the query'
      ],
      learningObjectives: [
        'Understand SQL injection vulnerabilities',
        'Learn to identify vulnerable login forms',
        'Practice SQL injection exploitation'
      ]
    }
  };
}

/**
 * Generate XSS challenge (Medium)
 */
function generateXSSChallenge(scenario) {
  const flag = `CTF{web_xss_stored_${generateRandomString(10)}}`;
  const title = scenario.title || 'XSS Challenge';

  const indexPHP = `<?php
// ${title}
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['comment'])) {
    $comment = $_POST['comment'];
    // Vulnerable: No sanitization
    $_SESSION['comments'][] = $comment;
}

$comments = $_SESSION['comments'] ?? [];
?>

<!DOCTYPE html>
<html>
<head>
    <title>Comment Board - ${title}</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; }
        .comment { border: 1px solid #ddd; padding: 10px; margin: 10px 0; }
        textarea { width: 100%; height: 100px; }
    </style>
</head>
<body>
    <h1>Comment Board</h1>
    <p>Leave a comment! (Admin will review)</p>
    
    <form method="POST">
        <textarea name="comment" placeholder="Your comment..." required></textarea><br>
        <button type="submit">Submit</button>
    </form>
    
    <h2>Comments:</h2>
    <?php foreach ($comments as $comment): ?>
        <div class="comment"><?= $comment ?></div>
    <?php endforeach; ?>
    
    <?php
    // Admin view - shows flag if admin cookie is set
    if (isset($_COOKIE['admin']) && $_COOKIE['admin'] === 'true') {
        echo "<div style='background: #ff0; padding: 20px; margin: 20px 0;'>";
        echo "<h3>Admin Panel</h3>";
        echo "<p>Flag: ${flag}</p>";
        echo "</div>";
    }
    ?>
</body>
</html>`;

  return {
    files: [
      {
        name: 'index.php',
        path: '',
        content: indexPHP
      },
      {
        name: 'README.txt',
        path: '',
        content: `XSS Challenge (Medium)

Objective:
Steal the admin cookie to access the admin panel and retrieve the flag.

Hints:
1. The comment board doesn't sanitize user input
2. Admin views all comments
3. You need to execute JavaScript in the admin's browser

Tools:
- Browser
- Burp Suite
- JavaScript knowledge

Flag Format: CTF{...}`
      }
    ],
    flag: flag,
    configuration: {
      vulnerability: 'xss',
      difficulty: 'medium',
      exploitPath: 'Inject XSS payload in comment to steal admin cookie, then set cookie and access admin panel',
      flagLocation: 'Admin panel (visible when admin cookie is set)',
      tools: ['burpsuite', 'browser'],
      setup: `apt-get update && apt-get install -y php apache2
cp /challenge/index.php /var/www/html/
service apache2 start`,
      hints: [
        'The comment board doesn\'t sanitize input',
        'Admin views all comments',
        'You need to execute JavaScript'
      ],
      learningObjectives: [
        'Understand stored XSS vulnerabilities',
        'Learn cookie theft techniques',
        'Practice XSS exploitation'
      ]
    }
  };
}

/**
 * Generate complex SQL injection challenge (Hard)
 */
function generateComplexSQLi(scenario) {
  const flag = `CTF{web_sqli_advanced_${generateRandomString(10)}}`;
  
  const indexPHP = `<?php
// Advanced SQL Injection Challenge
$conn = new mysqli("localhost", "root", "password", "ctf_db");

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $id = intval($_POST['id']); // Type casting - but still vulnerable
    $name = mysqli_real_escape_string($conn, $_POST['name']); // Escaped
    
    // Complex query with multiple conditions
    $sql = "SELECT * FROM products WHERE id = $id AND name LIKE '%$name%' AND status = 'active'";
    $result = $conn->query($sql);
    
    if ($result && $result->num_rows > 0) {
        while ($row = $result->fetch_assoc()) {
            echo "<p>Product: " . htmlspecialchars($row['name']) . "</p>";
        }
    }
    
    // Second query - vulnerable to UNION injection
    $search = $_GET['search'] ?? '';
    $sql2 = "SELECT id, name FROM products WHERE name LIKE '%$search%'";
    $result2 = $conn->query($sql2);
    // ... more complex logic
}
?>`;

  return {
    files: [
      {
        name: 'index.php',
        path: '',
        content: indexPHP
      },
      {
        name: 'database.sql',
        path: '',
        content: `CREATE DATABASE IF NOT EXISTS ctf_db;
USE ctf_db;
CREATE TABLE products (id INT, name VARCHAR(100), status VARCHAR(20));
CREATE TABLE secrets (id INT, flag VARCHAR(100));
INSERT INTO secrets VALUES (1, '${flag}');`
      }
    ],
    flag: flag,
    configuration: {
      vulnerability: 'sqli',
      difficulty: 'hard',
      exploitPath: 'Multiple injection points, need UNION SELECT to access secrets table',
      flagLocation: 'secrets table',
      tools: ['sqlmap', 'burpsuite'],
      setup: `apt-get update && apt-get install -y mysql-server php-mysql apache2
service mysql start
mysql < /challenge/database.sql
cp /challenge/index.php /var/www/html/
service apache2 start`,
      hints: [
        'Multiple injection points exist',
        'Type casting can be bypassed',
        'UNION SELECT is needed'
      ],
      learningObjectives: [
        'Understand advanced SQL injection',
        'Learn UNION-based exploitation',
        'Practice bypassing filters'
      ]
    }
  };
}

/**
 * Generate basic FTP challenge (Easy)
 */
function generateBasicFTP(scenario) {
  const flag = `CTF{network_ftp_anon_${generateRandomString(10)}}`;
  
  const ftpConfig = `# vsftpd configuration - Anonymous FTP
listen=YES
anonymous_enable=YES
anon_upload_enable=NO
anon_mkdir_write_enable=NO
anon_root=/ftp
no_anon_password=YES
write_enable=YES
local_enable=YES
chroot_local_user=YES
allow_writeable_chroot=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
pasv_enable=YES
pasv_min_port=21100
pasv_max_port=21110
userlist_enable=NO`;

  const startupScript = `#!/bin/bash
mkdir -p /ftp/public /ftp/data /ftp/private
echo "${flag}" > /ftp/data/flag.txt
chmod 644 /ftp/data/flag.txt
echo "Welcome to the CTF FTP Server!" > /ftp/public/welcome.txt
echo "Important files may be in subdirectories" > /ftp/public/readme.txt
service vsftpd start
tail -f /dev/null`;

  return {
    files: [
      {
        name: 'vsftpd.conf',
        path: '',
        content: ftpConfig
      },
      {
        name: 'start.sh',
        path: '',
        content: startupScript
      },
      {
        name: 'README.txt',
        path: '',
        content: `FTP Challenge (Easy)

Objective:
Connect to the FTP server and find the flag.

Hints:
1. Anonymous access is enabled
2. Explore all directories
3. Check subdirectories

Tools:
- ftp
- nmap
- wget/curl

Flag Format: CTF{...}`
      }
    ],
    flag: flag,
    configuration: {
      serviceType: 'ftp',
      difficulty: 'easy',
      misconfiguration: 'Anonymous FTP access enabled with sensitive files',
      exploitPath: 'Connect via anonymous FTP and navigate to /data directory',
      tools: ['nmap', 'ftp', 'wget'],
      servicePort: 21,
      setup: `apt-get update && apt-get install -y vsftpd
cp /challenge/vsftpd.conf /etc/vsftpd.conf
mkdir -p /var/run/vsftpd/empty
chmod +x /challenge/start.sh
/challenge/start.sh`,
      hints: [
        'Anonymous access is enabled',
        'Explore all directories',
        'Check subdirectories'
      ],
      learningObjectives: [
        'Understand FTP protocol',
        'Learn anonymous FTP access',
        'Practice directory enumeration'
      ]
    }
  };
}

/**
 * Generate SMB challenge (Medium)
 */
function generateSMBChallenge(scenario) {
  const flag = `CTF{network_smb_enum_${generateRandomString(10)}}`;
  
  const smbConfig = `[global]
workgroup = WORKGROUP
server string = CTF Server
security = user
map to guest = Bad User

[public]
path = /srv/smb/public
browseable = yes
read only = yes
guest ok = yes

[private]
path = /srv/smb/private
browseable = no
read only = yes
guest ok = yes

[secret]
path = /srv/smb/secret
browseable = no
read only = yes
guest ok = yes`;

  const startupScript = `#!/bin/bash
mkdir -p /srv/smb/{public,private,secret}
echo "${flag}" > /srv/smb/secret/flag.txt
chmod 644 /srv/smb/secret/flag.txt
echo "Public share" > /srv/smb/public/readme.txt
echo "Private share" > /srv/smb/private/readme.txt
service smbd start
tail -f /dev/null`;

  return {
    files: [
      {
        name: 'smb.conf',
        path: '',
        content: smbConfig
      },
      {
        name: 'start.sh',
        path: '',
        content: startupScript
      }
    ],
    flag: flag,
    configuration: {
      serviceType: 'smb',
      difficulty: 'medium',
      misconfiguration: 'Hidden shares accessible via enumeration',
      exploitPath: 'Enumerate SMB shares and access hidden secret share',
      tools: ['nmap', 'smbclient', 'enum4linux'],
      servicePort: 445,
      setup: `apt-get update && apt-get install -y samba
cp /challenge/smb.conf /etc/samba/smb.conf
chmod +x /challenge/start.sh
/challenge/start.sh`,
      hints: [
        'Enumerate all shares',
        'Some shares are hidden',
        'Check for guest access'
      ],
      learningObjectives: [
        'Understand SMB protocol',
        'Learn share enumeration',
        'Practice SMB exploitation'
      ]
    }
  };
}

/**
 * Generate SSH challenge (Hard)
 */
function generateSSHChallenge(scenario) {
  const flag = `CTF{network_ssh_weak_${generateRandomString(10)}}`;
  
  return {
    files: [
      {
        name: 'setup.sh',
        path: '',
        content: `#!/bin/bash
useradd -m -s /bin/bash user1
echo "user1:password123" | chpasswd
echo "${flag}" > /home/user1/flag.txt
chmod 600 /home/user1/flag.txt
service ssh start
tail -f /dev/null`
      }
    ],
    flag: flag,
    configuration: {
      serviceType: 'ssh',
      difficulty: 'hard',
      misconfiguration: 'Weak password, need to brute force',
      exploitPath: 'Brute force SSH with common passwords',
      tools: ['nmap', 'hydra', 'ssh'],
      servicePort: 22,
      setup: `apt-get update && apt-get install -y openssh-server
chmod +x /challenge/setup.sh
/challenge/setup.sh`,
      hints: [
        'Weak password policy',
        'Common passwords',
        'Brute force attack'
      ],
      learningObjectives: [
        'Understand SSH security',
        'Learn password brute forcing',
        'Practice SSH enumeration'
      ]
    }
  };
}

/**
 * Generate Caesar cipher (Easy)
 */
function generateCaesarCipher(scenario) {
  const flag = `CTF{crypto_caesar_${generateRandomString(10)}}`;
  const ciphertext = caesarEncode(flag, 13); // ROT13

  return {
    files: [
      {
        name: 'ciphertext.txt',
        path: '',
        content: ciphertext
      },
      {
        name: 'hint.txt',
        path: '',
        content: 'This looks like a rotation cipher. Try ROT13 or brute force all 26 rotations.'
      }
    ],
    flag: flag,
    configuration: {
      cryptoType: 'caesar',
      difficulty: 'easy',
      solvingMethod: 'Use ROT13 or try all 26 rotations',
      tools: ['tr', 'python', 'cyberchef'],
      setup: '',
      hints: [
        'Rotation cipher',
        'Try ROT13',
        'Or brute force all rotations'
      ],
      learningObjectives: [
        'Understand Caesar cipher',
        'Learn rotation ciphers',
        'Practice cipher decryption'
      ]
    }
  };
}

/**
 * Generate Vigenère cipher (Medium)
 */
function generateVigenereCipher(scenario) {
  const flag = `CTF{crypto_vigenere_${generateRandomString(10)}}`;
  const key = 'CTF';
  const ciphertext = vigenereEncode(flag, key);

  return {
    files: [
      {
        name: 'ciphertext.txt',
        path: '',
        content: ciphertext
      },
      {
        name: 'hint.txt',
        path: '',
        content: 'This is a polyalphabetic cipher. The key is a short word related to the challenge type.'
      }
    ],
    flag: flag,
    configuration: {
      cryptoType: 'vigenere',
      difficulty: 'medium',
      solvingMethod: 'Use Vigenère cipher decoder with key "CTF"',
      tools: ['python', 'cyberchef', 'dcode.fr'],
      setup: '',
      hints: [
        'Polyalphabetic cipher',
        'Short key word',
        'Related to challenge type'
      ],
      learningObjectives: [
        'Understand Vigenère cipher',
        'Learn polyalphabetic ciphers',
        'Practice key recovery'
      ]
    }
  };
}

/**
 * Generate RSA challenge (Hard)
 */
function generateRSAChallenge(scenario) {
  const flag = `CTF{crypto_rsa_weak_${generateRandomString(10)}}`;
  
  return {
    files: [
      {
        name: 'public.pem',
        path: '',
        content: '-----BEGIN PUBLIC KEY-----\n[Small RSA key - factorable]\n-----END PUBLIC KEY-----'
      },
      {
        name: 'encrypted.flag',
        path: '',
        content: '[Base64 encoded encrypted flag]'
      }
    ],
    flag: flag,
    configuration: {
      cryptoType: 'rsa',
      difficulty: 'hard',
      solvingMethod: 'Factor small RSA modulus and decrypt',
      tools: ['openssl', 'python', 'factordb'],
      setup: '',
      hints: [
        'Small key size',
        'Factor the modulus',
        'Use private key to decrypt'
      ],
      learningObjectives: [
        'Understand RSA encryption',
        'Learn RSA factorization',
        'Practice RSA decryption'
      ]
    }
  };
}

/**
 * Caesar cipher encoding
 */
function caesarEncode(text, shift) {
  return text.split('').map(char => {
    if (char.match(/[a-z]/i)) {
      const code = char.charCodeAt(0);
      const base = code >= 65 && code <= 90 ? 65 : 97;
      return String.fromCharCode(((code - base + shift) % 26) + base);
    }
    return char;
  }).join('');
}

/**
 * Vigenère cipher encoding
 */
function vigenereEncode(text, key) {
  const keyUpper = key.toUpperCase();
  let keyIndex = 0;
  
  return text.split('').map(char => {
    if (char.match(/[a-z]/i)) {
      const code = char.charCodeAt(0);
      const base = code >= 65 && code <= 90 ? 65 : 97;
      const keyChar = keyUpper[keyIndex % keyUpper.length];
      const keyShift = keyChar.charCodeAt(0) - 65;
      const encoded = ((code - base + keyShift) % 26) + base;
      keyIndex++;
      return String.fromCharCode(encoded);
    }
    return char;
  }).join('');
}

/**
 * Generate random string
 */
function generateRandomString(length) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789_';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

