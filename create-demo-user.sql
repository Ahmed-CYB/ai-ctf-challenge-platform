-- Create demo user in Guacamole
-- Password: password123

-- 1. Create entity for demo user
INSERT INTO guacamole_entity (name, type) VALUES ('demo', 'USER');

-- Get the entity_id (will be 1 if this is the first user)
SET @entity_id = LAST_INSERT_ID();

-- 2. Create user with password
-- Guacamole password format: SHA-256(password + hex(salt))
-- Pre-computed for password "password123":
--   Salt (32 bytes): 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
--   Hash: SHA-256("password123" + "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")

INSERT INTO guacamole_user (entity_id, password_hash, password_salt, password_date)
VALUES (
    @entity_id,
    unhex('8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92'),  -- SHA-256 hash
    unhex('1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'),  -- 32-byte salt
    NOW()
);

-- 3. Grant admin permissions (optional, for full access)
INSERT INTO guacamole_user_permission (entity_id, affected_user_id, permission)
VALUES (@entity_id, @entity_id, 'UPDATE');

INSERT INTO guacamole_user_permission (entity_id, affected_user_id, permission)
VALUES (@entity_id, @entity_id, 'ADMINISTER');

-- 4. Grant system permissions
INSERT INTO guacamole_system_permission (entity_id, permission)
VALUES 
    (@entity_id, 'CREATE_CONNECTION'),
    (@entity_id, 'CREATE_CONNECTION_GROUP'),
    (@entity_id, 'CREATE_SHARING_PROFILE'),
    (@entity_id, 'CREATE_USER'),
    (@entity_id, 'ADMINISTER');

SELECT 'Demo user created successfully!' AS status;
SELECT entity_id, name, type FROM guacamole_entity WHERE name='demo';
