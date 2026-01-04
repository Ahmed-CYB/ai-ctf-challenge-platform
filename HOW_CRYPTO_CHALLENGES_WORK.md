# How Cryptography Challenges Work

## 🔐 **Overview**

Cryptography challenges in the CTF platform are AI-generated puzzles that teach encryption, encoding, hashing, and cipher techniques. They can be file-based (static files) or web-based (interactive interfaces).

---

## 📋 **Supported Challenge Types**

### **1. Classical Ciphers**
- **Caesar Cipher**: Simple rotation cipher (ROT13, ROT47)
- **Vigenère Cipher**: Polyalphabetic substitution
- **Substitution Cipher**: Letter replacement
- **Transposition Cipher**: Character rearrangement

### **2. Modern Encryption**
- **RSA**: Public-key encryption with weak keys
- **AES**: Advanced Encryption Standard
- **DES**: Data Encryption Standard (weak keys)

### **3. Hash Cracking**
- **MD5**: Message Digest 5 (weak, fast to crack)
- **SHA**: Secure Hash Algorithm (SHA-1, SHA-256)
- **bcrypt**: Password hashing with weak passwords

### **4. Encoding Chains**
- **Base64 → Hex → ROT13**: Multiple encoding layers
- **URL Encoding**: Percent-encoded strings
- **Binary Encoding**: Binary to text conversions

### **5. Custom Ciphers**
- **XOR**: Exclusive OR operations
- **One-time Pad Misuse**: Incorrect implementation
- **Custom Algorithms**: Unique puzzle designs

---

## 🏗️ **How Challenges Are Created**

### **Step 1: User Request**
```
User: "create a crypto challenge"
User: "create a caesar cipher challenge"
User: "create an RSA encryption challenge"
```

### **Step 2: Classification**
The system identifies the challenge as `crypto` type and routes to:
- **Universal Structure Agent** → **Crypto Content Agent**

### **Step 3: Content Generation**
The **Crypto Content Agent** (`crypto-content-agent.js`) generates:

**Files:**
- `ciphertext.txt` - Encrypted/encoded data
- `hint.txt` - Progressive hints
- `key.txt` (optional) - Encryption keys
- `challenge.txt` - Challenge description
- Web interface files (if web-based)

**Configuration:**
```json
{
  "cryptoType": "caesar|vigenere|rsa|aes|...",
  "difficulty": "easy|medium|hard",
  "solvingMethod": "How to solve the challenge",
  "tools": ["hashcat", "john", "openssl", "python3"],
  "setup": "echo 'Crypto challenge files ready'"
}
```

### **Step 4: Challenge Structure**
```
challenges/{challenge-name}/
├── README.md              # Challenge description
├── metadata.json          # Challenge metadata
├── docker-compose.yml     # Container orchestration
├── victim-machine/
│   ├── Dockerfile         # Victim container
│   ├── ciphertext.txt    # Encrypted data
│   ├── hint.txt          # Hints
│   └── ...               # Other challenge files
└── attacker/
    └── Dockerfile.attacker  # Kali Linux with crypto tools
```

---

## 🛠️ **Tools Available on Attacker Machine**

When a crypto challenge is created, the attacker machine (Kali Linux) automatically gets:

### **Cryptography Tools:**
- **hashcat** - Advanced password recovery/hash cracking
- **john** (John the Ripper) - Password cracker
- **openssl** - Cryptographic toolkit
- **hashid** - Hash identifier
- **hash-identifier** - Identify hash types
- **python3-pycryptodome** - Python crypto library

### **General Tools:**
- **python3** - For custom scripts
- **curl/wget** - Download files
- **base64/hexdump** - Encoding/decoding
- **tr** - Text transformations (for Caesar ciphers)

---

## 🎯 **How Users Solve Crypto Challenges**

### **Step 1: Access the Challenge**

1. **Deploy the challenge:**
   ```
   deploy {challenge-name}
   ```

2. **Get Guacamole URL** from deployment response

3. **Access attacker machine** via Guacamole (Kali Linux)

### **Step 2: Access Challenge Files**

**Option A: File-Based Challenge**
```bash
# Files are in the victim container's /challenge directory
# Access via SSH or copy to attacker machine
docker exec {victim-container} cat /challenge/ciphertext.txt
```

**Option B: Web-Based Challenge**
```bash
# Access web interface
curl http://{victim-ip}/
# Or open in browser (if available)
```

### **Step 3: Identify the Cipher Type**

**Check hints:**
```bash
cat /challenge/hint.txt
```

**Analyze ciphertext:**
```bash
# Check if it's base64
echo "{ciphertext}" | base64 -d

# Check if it's hex
echo "{ciphertext}" | xxd -r -p

# Check if it's a hash
hashid "{ciphertext}"
hash-identifier "{ciphertext}"
```

### **Step 4: Decrypt/Decode**

**Classical Ciphers:**
```bash
# Caesar cipher (ROT13)
echo "{ciphertext}" | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# Try all rotations
for i in {1..25}; do
  echo "Rotation $i:"
  echo "{ciphertext}" | tr 'A-Za-z' "$(echo {A..Z} | cut -d' ' -f$((i+1))-26)$(echo {A..Z} | cut -d' ' -f1-$i)$(echo {a..z} | cut -d' ' -f$((i+1))-26)$(echo {a..z} | cut -d' ' -f1-$i)"
done

# Vigenère (requires key)
# Use online tools or Python script
python3 -c "from pycryptodome import ..."
```

**Hash Cracking:**
```bash
# Identify hash type
hashid "{hash}"

# Crack with hashcat
hashcat -m {hash-mode} {hash} /usr/share/wordlists/rockyou.txt

# Crack with John
john --format={format} {hash-file}
john --wordlist=/usr/share/wordlists/rockyou.txt {hash-file}
```

**RSA/AES:**
```bash
# RSA decryption
openssl rsautl -decrypt -inkey private.pem -in encrypted.bin

# AES decryption
openssl enc -aes-256-cbc -d -in encrypted.bin -out decrypted.txt -k "password"
```

**Encoding Chains:**
```bash
# Base64 decode
echo "{base64}" | base64 -d

# Hex decode
echo "{hex}" | xxd -r -p

# Multiple layers
echo "{encoded}" | base64 -d | xxd -r -p | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

### **Step 5: Extract the Flag**

The flag is embedded in the plaintext:
```
CTF{crypto_challenge_flag_2024}
```

---

## 📊 **Challenge Difficulty Levels**

### **Easy:**
- Single encoding (Base64, Hex, ROT13)
- Simple Caesar cipher
- Weak hash with common password
- Clear hints provided

**Example:**
```
Ciphertext: SFRCe2NyeXB0b19lYXN5XzIwMjR9
Solution: base64 decode → CTF{crypto_easy_2024}
```

### **Medium:**
- Multiple encoding layers
- Vigenère cipher (requires key finding)
- RSA with small key
- Hash with wordlist cracking

**Example:**
```
Ciphertext: Base64(Hex(ROT13("CTF{medium_challenge}")))
Solution: Multiple decoding steps
```

### **Hard:**
- Custom cipher algorithms
- Weak RSA implementation
- Padding oracle attacks
- Side-channel analysis
- Multi-stage decryption

**Example:**
```
Ciphertext: Custom XOR cipher with key derivation
Solution: Analyze algorithm, find key, decrypt
```

---

## 🔄 **Complete Workflow Example**

### **1. Create Challenge**
```
User: "create a caesar cipher challenge"
System: ✅ Challenge "ancient-cipher-vault" created successfully!
```

### **2. Deploy Challenge**
```
User: "deploy ancient-cipher-vault"
System: ✅ Challenge deployed!
  - Guacamole URL: http://localhost:8081/guacamole/#/client/123
  - Username: ctf_user_xxx
  - Password: random_pass_123
```

### **3. Solve Challenge**

**From attacker machine:**
```bash
# Access challenge files
docker exec ctf-ancient-cipher-vault-victim cat /challenge/ciphertext.txt
# Output: PGS{naqvpvg_pvcure_inyhg_2024}

# Check hint
docker exec ctf-ancient-cipher-vault-victim cat /challenge/hint.txt
# Output: "This is a rotation cipher. Try ROT13."

# Decrypt
echo "PGS{naqvpvg_pvcure_inyhg_2024}" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# Output: CTF{ancient_cipher_vault_2024}

# Flag found!
```

---

## 🎨 **Challenge Structure Examples**

### **File-Based Crypto Challenge:**
```
victim-machine/
├── ciphertext.txt        # Encrypted flag
├── hint.txt             # Progressive hints
├── key.txt              # Encryption key (if provided)
└── README.txt           # Challenge description
```

### **Web-Based Crypto Challenge:**
```
victim-machine/
├── app.py               # Flask/FastAPI web app
├── templates/
│   └── index.html       # Web interface
├── static/
│   └── style.css        # Styling
└── ciphertext.txt       # Encrypted data
```

---

## 🔧 **Technical Details**

### **Content Generation:**
- **AI Model**: Claude Sonnet 4 (Anthropic)
- **Temperature**: 0.8-1.0 (creative for uniqueness)
- **Max Tokens**: 12,000 (for large responses)
- **Retry Logic**: Up to 3 attempts if generation fails

### **Validation:**
- **Schema Validation**: Ensures all required fields
- **Quality Validation**: Checks for placeholders
- **Flag Validation**: Verifies flag format (CTF{...})
- **Setup Commands**: Mandatory (even if just echo)

### **Tool Installation:**
- Tools are automatically installed based on challenge category
- Database-driven tool mapping
- Dynamic tool allocation based on crypto type

---

## 💡 **Pro Tips for Solving**

1. **Start with identification:**
   - Use `hashid` or `hash-identifier` for hashes
   - Check file extensions and formats
   - Look for patterns in ciphertext

2. **Try common encodings first:**
   - Base64 (ends with `=` or `==`)
   - Hex (only 0-9, a-f characters)
   - URL encoding (`%XX` patterns)

3. **Use online tools:**
   - CyberChef (if available)
   - dCode.fr
   - Online hash crackers

4. **Write custom scripts:**
   ```python
   # Python script for custom ciphers
   from Crypto.Cipher import AES
   # ... decryption logic
   ```

5. **Check hints progressively:**
   - Start with first hint (vague)
   - Use later hints if stuck
   - Don't skip hints - they guide you

---

## ✅ **Success Criteria**

You've successfully solved a crypto challenge when you:
1. ✅ Can access the challenge files
2. ✅ Identified the cipher/encoding type
3. ✅ Applied the correct decryption method
4. ✅ Extracted the flag from plaintext
5. ✅ Flag matches format: `CTF{...}`

---

## 📝 **Example Challenge Types**

### **Caesar Cipher:**
- **Ciphertext**: `PGS{naqvpvg_pvcure}`
- **Method**: ROT13
- **Solution**: `CTF{ancient_cipher}`

### **Base64 Encoding:**
- **Ciphertext**: `Q1RGe2Jhc2U2NF9mbGFnfQ==`
- **Method**: Base64 decode
- **Solution**: `CTF{base64_flag}`

### **Hash Cracking:**
- **Hash**: `5f4dcc3b5aa765d61d8327deb882cf99`
- **Type**: MD5
- **Method**: `hashcat -m 0 hash.txt rockyou.txt`
- **Solution**: `password` → Flag: `CTF{password_cracked}`

### **RSA Challenge:**
- **Files**: `public.pem`, `encrypted.bin`
- **Method**: Extract private key or factor modulus
- **Solution**: Decrypt with private key

---

**Happy Hacking! 🔐**

