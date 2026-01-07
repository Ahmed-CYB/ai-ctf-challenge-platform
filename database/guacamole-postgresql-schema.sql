-- ============================================
-- Apache Guacamole PostgreSQL Schema
-- Converted from MySQL schema for PostgreSQL compatibility
-- ============================================
-- This schema is for a SEPARATE database: guacamole_db
-- DO NOT mix with the main CTF platform database (ctf_platform)
-- ============================================

-- Enable UUID extension if needed
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================
-- Table: guacamole_connection_group
-- ============================================
CREATE TABLE guacamole_connection_group (
    connection_group_id SERIAL PRIMARY KEY,
    parent_id INTEGER,
    connection_group_name VARCHAR(128) NOT NULL,
    type VARCHAR(20) NOT NULL DEFAULT 'ORGANIZATIONAL' 
        CHECK (type IN ('ORGANIZATIONAL', 'BALANCING')),
    max_connections INTEGER,
    max_connections_per_user INTEGER,
    enable_session_affinity BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT connection_group_name_parent UNIQUE (connection_group_name, parent_id),
    CONSTRAINT guacamole_connection_group_ibfk_1
        FOREIGN KEY (parent_id)
        REFERENCES guacamole_connection_group (connection_group_id) ON DELETE CASCADE
);

CREATE INDEX idx_connection_group_parent ON guacamole_connection_group(parent_id);

-- ============================================
-- Table: guacamole_connection
-- ============================================
CREATE TABLE guacamole_connection (
    connection_id SERIAL PRIMARY KEY,
    connection_name VARCHAR(128) NOT NULL,
    parent_id INTEGER,
    protocol VARCHAR(32) NOT NULL,
    proxy_port INTEGER,
    proxy_hostname VARCHAR(512),
    proxy_encryption_method VARCHAR(10) CHECK (proxy_encryption_method IN ('NONE', 'SSL')),
    max_connections INTEGER,
    max_connections_per_user INTEGER,
    connection_weight INTEGER,
    failover_only BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT connection_name_parent UNIQUE (connection_name, parent_id),
    CONSTRAINT guacamole_connection_ibfk_1
        FOREIGN KEY (parent_id)
        REFERENCES guacamole_connection_group (connection_group_id) ON DELETE CASCADE
);

CREATE INDEX idx_connection_parent ON guacamole_connection(parent_id);

-- ============================================
-- Table: guacamole_entity
-- ============================================
CREATE TABLE guacamole_entity (
    entity_id SERIAL PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    type VARCHAR(20) NOT NULL CHECK (type IN ('USER', 'USER_GROUP')),
    CONSTRAINT guacamole_entity_name_scope UNIQUE (type, name)
);

-- ============================================
-- Table: guacamole_user
-- ============================================
CREATE TABLE guacamole_user (
    user_id SERIAL PRIMARY KEY,
    entity_id INTEGER NOT NULL,
    password_hash BYTEA NOT NULL,
    password_salt BYTEA,
    password_date TIMESTAMP NOT NULL,
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    expired BOOLEAN NOT NULL DEFAULT FALSE,
    access_window_start TIME,
    access_window_end TIME,
    valid_from DATE,
    valid_until DATE,
    timezone VARCHAR(64),
    full_name VARCHAR(256),
    email_address VARCHAR(256),
    organization VARCHAR(256),
    organizational_role VARCHAR(256),
    CONSTRAINT guacamole_user_single_entity UNIQUE (entity_id),
    CONSTRAINT guacamole_user_entity
        FOREIGN KEY (entity_id)
        REFERENCES guacamole_entity (entity_id) ON DELETE CASCADE
);

CREATE INDEX idx_user_entity ON guacamole_user(entity_id);

-- ============================================
-- Table: guacamole_user_group
-- ============================================
CREATE TABLE guacamole_user_group (
    user_group_id SERIAL PRIMARY KEY,
    entity_id INTEGER NOT NULL,
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT guacamole_user_group_single_entity UNIQUE (entity_id),
    CONSTRAINT guacamole_user_group_entity
        FOREIGN KEY (entity_id)
        REFERENCES guacamole_entity (entity_id) ON DELETE CASCADE
);

CREATE INDEX idx_user_group_entity ON guacamole_user_group(entity_id);

-- ============================================
-- Table: guacamole_user_group_member
-- ============================================
CREATE TABLE guacamole_user_group_member (
    user_group_id INTEGER NOT NULL,
    member_entity_id INTEGER NOT NULL,
    PRIMARY KEY (user_group_id, member_entity_id),
    CONSTRAINT guacamole_user_group_member_parent_id
        FOREIGN KEY (user_group_id)
        REFERENCES guacamole_user_group (user_group_id) ON DELETE CASCADE,
    CONSTRAINT guacamole_user_group_member_entity_id
        FOREIGN KEY (member_entity_id)
        REFERENCES guacamole_entity (entity_id) ON DELETE CASCADE
);

CREATE INDEX idx_user_group_member_entity ON guacamole_user_group_member(member_entity_id);

-- ============================================
-- Table: guacamole_sharing_profile
-- ============================================
CREATE TABLE guacamole_sharing_profile (
    sharing_profile_id SERIAL PRIMARY KEY,
    sharing_profile_name VARCHAR(128) NOT NULL,
    primary_connection_id INTEGER NOT NULL,
    CONSTRAINT sharing_profile_name_primary UNIQUE (sharing_profile_name, primary_connection_id),
    CONSTRAINT guacamole_sharing_profile_ibfk_1
        FOREIGN KEY (primary_connection_id)
        REFERENCES guacamole_connection (connection_id) ON DELETE CASCADE
);

CREATE INDEX idx_sharing_profile_connection ON guacamole_sharing_profile(primary_connection_id);

-- ============================================
-- Table: guacamole_connection_parameter
-- ============================================
CREATE TABLE guacamole_connection_parameter (
    connection_id INTEGER NOT NULL,
    parameter_name VARCHAR(128) NOT NULL,
    parameter_value VARCHAR(4096) NOT NULL,
    PRIMARY KEY (connection_id, parameter_name),
    CONSTRAINT guacamole_connection_parameter_ibfk_1
        FOREIGN KEY (connection_id)
        REFERENCES guacamole_connection (connection_id) ON DELETE CASCADE
);

-- ============================================
-- Table: guacamole_sharing_profile_parameter
-- ============================================
CREATE TABLE guacamole_sharing_profile_parameter (
    sharing_profile_id INTEGER NOT NULL,
    parameter_name VARCHAR(128) NOT NULL,
    parameter_value VARCHAR(4096) NOT NULL,
    PRIMARY KEY (sharing_profile_id, parameter_name),
    CONSTRAINT guacamole_sharing_profile_parameter_ibfk_1
        FOREIGN KEY (sharing_profile_id)
        REFERENCES guacamole_sharing_profile (sharing_profile_id) ON DELETE CASCADE
);

-- ============================================
-- Table: guacamole_user_attribute
-- ============================================
CREATE TABLE guacamole_user_attribute (
    user_id INTEGER NOT NULL,
    attribute_name VARCHAR(128) NOT NULL,
    attribute_value VARCHAR(4096) NOT NULL,
    PRIMARY KEY (user_id, attribute_name),
    CONSTRAINT guacamole_user_attribute_ibfk_1
        FOREIGN KEY (user_id)
        REFERENCES guacamole_user (user_id) ON DELETE CASCADE
);

CREATE INDEX idx_user_attribute_user ON guacamole_user_attribute(user_id);

-- ============================================
-- Table: guacamole_user_group_attribute
-- ============================================
CREATE TABLE guacamole_user_group_attribute (
    user_group_id INTEGER NOT NULL,
    attribute_name VARCHAR(128) NOT NULL,
    attribute_value VARCHAR(4096) NOT NULL,
    PRIMARY KEY (user_group_id, attribute_name),
    CONSTRAINT guacamole_user_group_attribute_ibfk_1
        FOREIGN KEY (user_group_id)
        REFERENCES guacamole_user_group (user_group_id) ON DELETE CASCADE
);

CREATE INDEX idx_user_group_attribute_group ON guacamole_user_group_attribute(user_group_id);

-- ============================================
-- Table: guacamole_connection_attribute
-- ============================================
CREATE TABLE guacamole_connection_attribute (
    connection_id INTEGER NOT NULL,
    attribute_name VARCHAR(128) NOT NULL,
    attribute_value VARCHAR(4096) NOT NULL,
    PRIMARY KEY (connection_id, attribute_name),
    CONSTRAINT guacamole_connection_attribute_ibfk_1
        FOREIGN KEY (connection_id)
        REFERENCES guacamole_connection (connection_id) ON DELETE CASCADE
);

CREATE INDEX idx_connection_attribute_connection ON guacamole_connection_attribute(connection_id);

-- ============================================
-- Table: guacamole_connection_group_attribute
-- ============================================
CREATE TABLE guacamole_connection_group_attribute (
    connection_group_id INTEGER NOT NULL,
    attribute_name VARCHAR(128) NOT NULL,
    attribute_value VARCHAR(4096) NOT NULL,
    PRIMARY KEY (connection_group_id, attribute_name),
    CONSTRAINT guacamole_connection_group_attribute_ibfk_1
        FOREIGN KEY (connection_group_id)
        REFERENCES guacamole_connection_group (connection_group_id) ON DELETE CASCADE
);

CREATE INDEX idx_connection_group_attribute_group ON guacamole_connection_group_attribute(connection_group_id);

-- ============================================
-- Table: guacamole_sharing_profile_attribute
-- ============================================
CREATE TABLE guacamole_sharing_profile_attribute (
    sharing_profile_id INTEGER NOT NULL,
    attribute_name VARCHAR(128) NOT NULL,
    attribute_value VARCHAR(4096) NOT NULL,
    PRIMARY KEY (sharing_profile_id, attribute_name),
    CONSTRAINT guacamole_sharing_profile_attribute_ibfk_1
        FOREIGN KEY (sharing_profile_id)
        REFERENCES guacamole_sharing_profile (sharing_profile_id) ON DELETE CASCADE
);

CREATE INDEX idx_sharing_profile_attribute_profile ON guacamole_sharing_profile_attribute(sharing_profile_id);

-- ============================================
-- Table: guacamole_connection_permission
-- ============================================
CREATE TABLE guacamole_connection_permission (
    entity_id INTEGER NOT NULL,
    connection_id INTEGER NOT NULL,
    permission VARCHAR(20) NOT NULL CHECK (permission IN ('READ', 'UPDATE', 'DELETE', 'ADMINISTER')),
    PRIMARY KEY (entity_id, connection_id, permission),
    CONSTRAINT guacamole_connection_permission_ibfk_1
        FOREIGN KEY (connection_id)
        REFERENCES guacamole_connection (connection_id) ON DELETE CASCADE,
    CONSTRAINT guacamole_connection_permission_entity
        FOREIGN KEY (entity_id)
        REFERENCES guacamole_entity (entity_id) ON DELETE CASCADE
);

CREATE INDEX idx_connection_permission_connection ON guacamole_connection_permission(connection_id);
CREATE INDEX idx_connection_permission_entity ON guacamole_connection_permission(entity_id);

-- ============================================
-- Table: guacamole_connection_group_permission
-- ============================================
CREATE TABLE guacamole_connection_group_permission (
    entity_id INTEGER NOT NULL,
    connection_group_id INTEGER NOT NULL,
    permission VARCHAR(20) NOT NULL CHECK (permission IN ('READ', 'UPDATE', 'DELETE', 'ADMINISTER')),
    PRIMARY KEY (entity_id, connection_group_id, permission),
    CONSTRAINT guacamole_connection_group_permission_ibfk_1
        FOREIGN KEY (connection_group_id)
        REFERENCES guacamole_connection_group (connection_group_id) ON DELETE CASCADE,
    CONSTRAINT guacamole_connection_group_permission_entity
        FOREIGN KEY (entity_id)
        REFERENCES guacamole_entity (entity_id) ON DELETE CASCADE
);

CREATE INDEX idx_connection_group_permission_group ON guacamole_connection_group_permission(connection_group_id);
CREATE INDEX idx_connection_group_permission_entity ON guacamole_connection_group_permission(entity_id);

-- ============================================
-- Table: guacamole_sharing_profile_permission
-- ============================================
CREATE TABLE guacamole_sharing_profile_permission (
    entity_id INTEGER NOT NULL,
    sharing_profile_id INTEGER NOT NULL,
    permission VARCHAR(20) NOT NULL CHECK (permission IN ('READ', 'UPDATE', 'DELETE', 'ADMINISTER')),
    PRIMARY KEY (entity_id, sharing_profile_id, permission),
    CONSTRAINT guacamole_sharing_profile_permission_ibfk_1
        FOREIGN KEY (sharing_profile_id)
        REFERENCES guacamole_sharing_profile (sharing_profile_id) ON DELETE CASCADE,
    CONSTRAINT guacamole_sharing_profile_permission_entity
        FOREIGN KEY (entity_id)
        REFERENCES guacamole_entity (entity_id) ON DELETE CASCADE
);

CREATE INDEX idx_sharing_profile_permission_profile ON guacamole_sharing_profile_permission(sharing_profile_id);
CREATE INDEX idx_sharing_profile_permission_entity ON guacamole_sharing_profile_permission(entity_id);

-- ============================================
-- Table: guacamole_system_permission
-- ============================================
CREATE TABLE guacamole_system_permission (
    entity_id INTEGER NOT NULL,
    permission VARCHAR(50) NOT NULL CHECK (permission IN (
        'CREATE_CONNECTION',
        'CREATE_CONNECTION_GROUP',
        'CREATE_SHARING_PROFILE',
        'CREATE_USER',
        'CREATE_USER_GROUP',
        'AUDIT',
        'ADMINISTER'
    )),
    PRIMARY KEY (entity_id, permission),
    CONSTRAINT guacamole_system_permission_entity
        FOREIGN KEY (entity_id)
        REFERENCES guacamole_entity (entity_id) ON DELETE CASCADE
);

CREATE INDEX idx_system_permission_entity ON guacamole_system_permission(entity_id);

-- ============================================
-- Table: guacamole_user_permission
-- ============================================
CREATE TABLE guacamole_user_permission (
    entity_id INTEGER NOT NULL,
    affected_user_id INTEGER NOT NULL,
    permission VARCHAR(20) NOT NULL CHECK (permission IN ('READ', 'UPDATE', 'DELETE', 'ADMINISTER')),
    PRIMARY KEY (entity_id, affected_user_id, permission),
    CONSTRAINT guacamole_user_permission_ibfk_1
        FOREIGN KEY (affected_user_id)
        REFERENCES guacamole_user (user_id) ON DELETE CASCADE,
    CONSTRAINT guacamole_user_permission_entity
        FOREIGN KEY (entity_id)
        REFERENCES guacamole_entity (entity_id) ON DELETE CASCADE
);

CREATE INDEX idx_user_permission_user ON guacamole_user_permission(affected_user_id);
CREATE INDEX idx_user_permission_entity ON guacamole_user_permission(entity_id);

-- ============================================
-- Table: guacamole_user_group_permission
-- ============================================
CREATE TABLE guacamole_user_group_permission (
    entity_id INTEGER NOT NULL,
    affected_user_group_id INTEGER NOT NULL,
    permission VARCHAR(20) NOT NULL CHECK (permission IN ('READ', 'UPDATE', 'DELETE', 'ADMINISTER')),
    PRIMARY KEY (entity_id, affected_user_group_id, permission),
    CONSTRAINT guacamole_user_group_permission_affected_user_group
        FOREIGN KEY (affected_user_group_id)
        REFERENCES guacamole_user_group (user_group_id) ON DELETE CASCADE,
    CONSTRAINT guacamole_user_group_permission_entity
        FOREIGN KEY (entity_id)
        REFERENCES guacamole_entity (entity_id) ON DELETE CASCADE
);

CREATE INDEX idx_user_group_permission_group ON guacamole_user_group_permission(affected_user_group_id);
CREATE INDEX idx_user_group_permission_entity ON guacamole_user_group_permission(entity_id);

-- ============================================
-- Table: guacamole_connection_history
-- ============================================
CREATE TABLE guacamole_connection_history (
    history_id SERIAL PRIMARY KEY,
    user_id INTEGER,
    username VARCHAR(128) NOT NULL,
    remote_host VARCHAR(256),
    connection_id INTEGER,
    connection_name VARCHAR(128) NOT NULL,
    sharing_profile_id INTEGER,
    sharing_profile_name VARCHAR(128),
    start_date TIMESTAMP NOT NULL,
    end_date TIMESTAMP,
    CONSTRAINT guacamole_connection_history_ibfk_1
        FOREIGN KEY (user_id)
        REFERENCES guacamole_user (user_id) ON DELETE SET NULL,
    CONSTRAINT guacamole_connection_history_ibfk_2
        FOREIGN KEY (connection_id)
        REFERENCES guacamole_connection (connection_id) ON DELETE SET NULL,
    CONSTRAINT guacamole_connection_history_ibfk_3
        FOREIGN KEY (sharing_profile_id)
        REFERENCES guacamole_sharing_profile (sharing_profile_id) ON DELETE SET NULL
);

CREATE INDEX idx_connection_history_user ON guacamole_connection_history(user_id);
CREATE INDEX idx_connection_history_connection ON guacamole_connection_history(connection_id);
CREATE INDEX idx_connection_history_sharing_profile ON guacamole_connection_history(sharing_profile_id);
CREATE INDEX idx_connection_history_start_date ON guacamole_connection_history(start_date);
CREATE INDEX idx_connection_history_end_date ON guacamole_connection_history(end_date);
CREATE INDEX idx_connection_history_connection_start ON guacamole_connection_history(connection_id, start_date);

-- ============================================
-- Table: guacamole_user_history
-- ============================================
CREATE TABLE guacamole_user_history (
    history_id SERIAL PRIMARY KEY,
    user_id INTEGER,
    username VARCHAR(128) NOT NULL,
    remote_host VARCHAR(256),
    start_date TIMESTAMP NOT NULL,
    end_date TIMESTAMP,
    CONSTRAINT guacamole_user_history_ibfk_1
        FOREIGN KEY (user_id)
        REFERENCES guacamole_user (user_id) ON DELETE SET NULL
);

CREATE INDEX idx_user_history_user ON guacamole_user_history(user_id);
CREATE INDEX idx_user_history_start_date ON guacamole_user_history(start_date);
CREATE INDEX idx_user_history_end_date ON guacamole_user_history(end_date);
CREATE INDEX idx_user_history_user_start ON guacamole_user_history(user_id, start_date);

-- ============================================
-- Table: guacamole_user_password_history
-- ============================================
CREATE TABLE guacamole_user_password_history (
    password_history_id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    password_hash BYTEA NOT NULL,
    password_salt BYTEA,
    password_date TIMESTAMP NOT NULL,
    CONSTRAINT guacamole_user_password_history_ibfk_1
        FOREIGN KEY (user_id)
        REFERENCES guacamole_user (user_id) ON DELETE CASCADE
);

CREATE INDEX idx_password_history_user ON guacamole_user_password_history(user_id);

-- ============================================
-- Initial Data: Create default admin user
-- ============================================
-- Default user "guacadmin" with password "guacadmin"
INSERT INTO guacamole_entity (name, type) VALUES ('guacadmin', 'USER');

INSERT INTO guacamole_user (entity_id, password_hash, password_salt, password_date)
SELECT
    entity_id,
    '\xCA458A7D494E3BE824F5E1E175A1556C0F8EEF2C2D7DF3633BEC4A29C4411960'::bytea,  -- 'guacadmin'
    '\xFE24ADC5E11E2B25288D1704ABE67A79E342ECC26064CE69C5B3177795A82264'::bytea,
    NOW()
FROM guacamole_entity WHERE name = 'guacadmin';

-- Grant all system permissions to guacadmin
INSERT INTO guacamole_system_permission (entity_id, permission)
SELECT entity_id, permission
FROM (
    SELECT 'guacadmin' AS username, 'CREATE_CONNECTION' AS permission
    UNION SELECT 'guacadmin', 'CREATE_CONNECTION_GROUP'
    UNION SELECT 'guacadmin', 'CREATE_SHARING_PROFILE'
    UNION SELECT 'guacadmin', 'CREATE_USER'
    UNION SELECT 'guacadmin', 'CREATE_USER_GROUP'
    UNION SELECT 'guacadmin', 'ADMINISTER'
) permissions
JOIN guacamole_entity ON permissions.username = guacamole_entity.name AND guacamole_entity.type = 'USER';

-- Grant admin permission to read/update/administer self
INSERT INTO guacamole_user_permission (entity_id, affected_user_id, permission)
SELECT guacamole_entity.entity_id, guacamole_user.user_id, permission
FROM (
    SELECT 'guacadmin' AS username, 'guacadmin' AS affected_username, 'READ' AS permission
    UNION SELECT 'guacadmin', 'guacadmin', 'UPDATE'
    UNION SELECT 'guacadmin', 'guacadmin', 'ADMINISTER'
) permissions
JOIN guacamole_entity ON permissions.username = guacamole_entity.name AND guacamole_entity.type = 'USER'
JOIN guacamole_entity affected ON permissions.affected_username = affected.name AND affected.type = 'USER'
JOIN guacamole_user ON guacamole_user.entity_id = affected.entity_id;

-- ============================================
-- END OF SCHEMA
-- ============================================

