-- Package and Service Mappings System
-- Dynamic configuration for service-to-package mappings, OS-specific packages, and tool classifications
-- Allows automation to update mappings without code changes

-- ============================================
-- SERVICE TO PACKAGE MAPPINGS
-- ============================================
-- Maps service names to their package names across different OS types
CREATE TABLE IF NOT EXISTS service_package_mappings (
    id SERIAL PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,           -- e.g., 'ftp', 'ssh', 'smb'
    package_name VARCHAR(200),                     -- Default package name (Debian/Ubuntu)
    alpine_package VARCHAR(200),                    -- Alpine Linux package name
    rhel_package VARCHAR(200),                     -- RHEL/CentOS/Rocky package name
    is_valid BOOLEAN DEFAULT TRUE,                 -- Some services aren't packages (null package_name)
    description TEXT,
    service_type VARCHAR(50),                          -- 'service', 'protocol', 'tool'
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    CONSTRAINT service_package_mappings_service_name_key UNIQUE (service_name)
);

-- ============================================
-- PACKAGE ALIASES
-- ============================================
-- Maps common package name variations to correct package names
CREATE TABLE IF NOT EXISTS package_aliases (
    id SERIAL PRIMARY KEY,
    alias VARCHAR(100) NOT NULL,                   -- e.g., 'mysql-server'
    actual_package VARCHAR(200) NOT NULL,          -- e.g., 'mariadb-server'
    os_type VARCHAR(50) DEFAULT 'all',            -- 'all', 'debian', 'alpine', 'rhel', 'kali'
    created_at TIMESTAMP DEFAULT NOW(),
    
    CONSTRAINT package_aliases_alias_key UNIQUE (alias, os_type)
);

-- ============================================
-- ATTACK TOOLS CLASSIFICATION
-- ============================================
-- Tools that should ONLY be on attacker machines, never on victims
CREATE TABLE IF NOT EXISTS attack_tools (
    id SERIAL PRIMARY KEY,
    tool_name VARCHAR(100) NOT NULL UNIQUE,
    category VARCHAR(50),                          -- 'network', 'web', 'crypto', 'forensics', etc.
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- ============================================
-- INVALID SERVICE NAMES
-- ============================================
-- Service/protocol names that are NOT packages (e.g., netbios-ns is part of Samba)
CREATE TABLE IF NOT EXISTS invalid_service_names (
    id SERIAL PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL UNIQUE,
    reason TEXT,                                    -- Why it's invalid (e.g., 'part of samba', 'xinetd service')
    parent_package VARCHAR(200),                    -- What package provides it (if applicable)
    created_at TIMESTAMP DEFAULT NOW()
);

-- ============================================
-- BASE TOOLS BY OS TYPE
-- ============================================
-- Essential tools that should be installed on all machines of a given OS type
CREATE TABLE IF NOT EXISTS base_tools_by_os (
    id SERIAL PRIMARY KEY,
    os_type VARCHAR(50) NOT NULL,                  -- 'apt-get', 'apk', 'dnf', 'yum', 'pacman'
    package_manager VARCHAR(50) NOT NULL,          -- Same as os_type for clarity
    tools TEXT[] NOT NULL,                          -- Array of package names
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    CONSTRAINT base_tools_by_os_os_type_key UNIQUE (os_type)
);

-- ============================================
-- TOOL CATEGORIES
-- ============================================
-- Maps tools to their categories for automatic tool selection
CREATE TABLE IF NOT EXISTS tool_categories (
    id SERIAL PRIMARY KEY,
    tool_name VARCHAR(100) NOT NULL,
    category VARCHAR(50) NOT NULL,                  -- 'network', 'web', 'crypto', 'forensics', 'pwn', 'misc'
    priority INTEGER DEFAULT 0,                     -- Higher priority = more essential
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    CONSTRAINT tool_categories_tool_category_key UNIQUE (tool_name, category)
);

-- ============================================
-- TOOL TO PACKAGE MAPPINGS (Kali/Attacker)
-- ============================================
-- Maps tool names to their Kali Linux package names
CREATE TABLE IF NOT EXISTS tool_package_mappings (
    id SERIAL PRIMARY KEY,
    tool_name VARCHAR(100) NOT NULL,
    package_name VARCHAR(200) NOT NULL,
    os_type VARCHAR(50) DEFAULT 'kali',            -- 'kali', 'debian', 'ubuntu', etc.
    category VARCHAR(50),                          -- 'network', 'web', 'crypto', etc.
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    CONSTRAINT tool_package_mappings_tool_os_key UNIQUE (tool_name, os_type)
);

-- ============================================
-- INDEXES
-- ============================================
CREATE INDEX IF NOT EXISTS idx_service_mappings_service_name ON service_package_mappings(service_name);
CREATE INDEX IF NOT EXISTS idx_service_mappings_is_valid ON service_package_mappings(is_valid);
CREATE INDEX IF NOT EXISTS idx_package_aliases_alias ON package_aliases(alias);
CREATE INDEX IF NOT EXISTS idx_package_aliases_os_type ON package_aliases(os_type);
CREATE INDEX IF NOT EXISTS idx_attack_tools_tool_name ON attack_tools(tool_name);
CREATE INDEX IF NOT EXISTS idx_attack_tools_category ON attack_tools(category);
CREATE INDEX IF NOT EXISTS idx_attack_tools_is_active ON attack_tools(is_active);
CREATE INDEX IF NOT EXISTS idx_invalid_service_names_service ON invalid_service_names(service_name);
CREATE INDEX IF NOT EXISTS idx_base_tools_os_type ON base_tools_by_os(os_type);
CREATE INDEX IF NOT EXISTS idx_tool_categories_tool ON tool_categories(tool_name);
CREATE INDEX IF NOT EXISTS idx_tool_categories_category ON tool_categories(category);
CREATE INDEX IF NOT EXISTS idx_tool_package_mappings_tool ON tool_package_mappings(tool_name);
CREATE INDEX IF NOT EXISTS idx_tool_package_mappings_category ON tool_package_mappings(category);

-- ============================================
-- TRIGGERS
-- ============================================
-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_package_mappings_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Drop triggers if they exist (to handle re-runs)
DROP TRIGGER IF EXISTS trigger_update_service_mappings_updated_at ON service_package_mappings;
CREATE TRIGGER trigger_update_service_mappings_updated_at
BEFORE UPDATE ON service_package_mappings
FOR EACH ROW
EXECUTE FUNCTION update_package_mappings_updated_at();

DROP TRIGGER IF EXISTS trigger_update_attack_tools_updated_at ON attack_tools;
CREATE TRIGGER trigger_update_attack_tools_updated_at
BEFORE UPDATE ON attack_tools
FOR EACH ROW
EXECUTE FUNCTION update_package_mappings_updated_at();

DROP TRIGGER IF EXISTS trigger_update_base_tools_updated_at ON base_tools_by_os;
CREATE TRIGGER trigger_update_base_tools_updated_at
BEFORE UPDATE ON base_tools_by_os
FOR EACH ROW
EXECUTE FUNCTION update_package_mappings_updated_at();

DROP TRIGGER IF EXISTS trigger_update_tool_categories_updated_at ON tool_categories;
CREATE TRIGGER trigger_update_tool_categories_updated_at
BEFORE UPDATE ON tool_categories
FOR EACH ROW
EXECUTE FUNCTION update_package_mappings_updated_at();

DROP TRIGGER IF EXISTS trigger_update_tool_package_mappings_updated_at ON tool_package_mappings;
CREATE TRIGGER trigger_update_tool_package_mappings_updated_at
BEFORE UPDATE ON tool_package_mappings
FOR EACH ROW
EXECUTE FUNCTION update_package_mappings_updated_at();

-- ============================================
-- SEED DATA: Service to Package Mappings
-- ============================================
INSERT INTO service_package_mappings (service_name, package_name, alpine_package, rhel_package, is_valid, description, service_type) VALUES
('ftp', 'vsftpd', 'vsftpd', 'vsftpd', true, 'FTP server', 'service'),
('ssh', 'openssh-server', 'openssh', 'openssh-server', true, 'SSH server', 'service'),
('web', 'apache2', 'apache2', 'httpd', true, 'Web server', 'service'),
('web-server', 'apache2', 'apache2', 'httpd', true, 'Web server', 'service'),
('http', 'apache2', 'apache2', 'httpd', true, 'HTTP server', 'service'),
('database', 'mariadb-server', 'mariadb', 'mariadb-server', true, 'Database server', 'service'),
('mysql', 'mariadb-server', 'mariadb', 'mariadb-server', true, 'MySQL/MariaDB server', 'service'),
('smb', 'samba', 'samba', 'samba', true, 'SMB/CIFS server', 'service'),
('samba', 'samba', 'samba', 'samba', true, 'Samba file server', 'service'),
('rdp', 'xrdp', 'xrdp', 'xrdp', true, 'RDP server', 'service'),
('tftp', 'tftp-hpa', 'tftp-hpa', 'tftp', true, 'TFTP server', 'service'),
('telnet', 'telnet', 'telnet', 'telnet-server', true, 'Telnet server', 'service'),
('rsh', 'rsh-server', 'rsh-server', 'rsh-server', true, 'RSH server', 'service'),
('finger', 'fingerd', 'fingerd', 'finger', true, 'Finger daemon', 'service'),
('nfs', 'nfs-common', 'nfs-utils', 'nfs-utils', true, 'NFS client', 'service'),
('snmp', 'snmp', 'net-snmp', 'net-snmp', true, 'SNMP service', 'service'),
('ldap', 'slapd', 'openldap', 'openldap-servers', true, 'LDAP server', 'service'),
('dns', 'bind9', 'bind', 'bind', true, 'DNS server', 'service'),
('echo', NULL, NULL, NULL, false, 'xinetd service, not a package', 'protocol'),
('discard', NULL, NULL, NULL, false, 'xinetd service, not a package', 'protocol'),
('chargen', NULL, NULL, NULL, false, 'xinetd service, not a package', 'protocol'),
('netbios', NULL, NULL, NULL, false, 'Part of Samba, not a separate package', 'protocol'),
('netbios-ns', NULL, NULL, NULL, false, 'Part of Samba, not a separate package', 'protocol'),
('netbios-ssn', NULL, NULL, NULL, false, 'Part of Samba, not a separate package', 'protocol'),
('netbios-dgm', NULL, NULL, NULL, false, 'Part of Samba, not a separate package', 'protocol'),
('cifs', NULL, NULL, NULL, false, 'Protocol, comes with Samba', 'protocol'),
('smb2', NULL, NULL, NULL, false, 'Protocol, comes with Samba', 'protocol'),
('smb3', NULL, NULL, NULL, false, 'Protocol, comes with Samba', 'protocol')
ON CONFLICT (service_name) DO NOTHING;

-- ============================================
-- SEED DATA: Package Aliases
-- ============================================
INSERT INTO package_aliases (alias, actual_package, os_type) VALUES
('mysql-server', 'mariadb-server', 'all'),
('mysql-client', 'mariadb-client', 'all'),
('mysql', 'mariadb-server', 'all'),
('database', 'mariadb-server', 'all'),
('db-server', 'mariadb-server', 'all'),
('web-server', 'apache2', 'all'),
('http-server', 'apache2', 'all'),
('postgresql', 'postgresql postgresql-contrib', 'all'),
('postgres', 'postgresql postgresql-contrib', 'all'),
('netcat', 'netcat-traditional', 'debian'),
('netcat', 'netcat-openbsd', 'alpine'),
('netcat', 'nc', 'rhel'),
('nc', 'netcat-traditional', 'debian'),
('nc', 'netcat-openbsd', 'alpine'),
('nc', 'nc', 'rhel'),
('openssh-server', 'openssh', 'alpine'),
('mariadb-server', 'mariadb', 'alpine'),
('apache2', 'httpd', 'rhel'),
('bind9', 'bind', 'alpine'),
('bind9', 'bind', 'rhel'),
('telnet', 'telnet-server', 'rhel')
ON CONFLICT (alias, os_type) DO NOTHING;

-- ============================================
-- SEED DATA: Attack Tools (should only be on attackers)
-- ============================================
INSERT INTO attack_tools (tool_name, category, description) VALUES
('nmap', 'network', 'Network mapper and port scanner'),
('netcat', 'network', 'Network utility for reading/writing network connections'),
('nc', 'network', 'Netcat alias'),
('ping', 'network', 'Network connectivity testing tool'),
('traceroute', 'network', 'Network path tracing tool'),
('tcpdump', 'network', 'Packet analyzer'),
('wireshark', 'network', 'Network protocol analyzer'),
('tshark', 'network', 'Command-line version of Wireshark'),
('masscan', 'network', 'Fast port scanner'),
('hping3', 'network', 'Network packet crafting tool'),
('arp-scan', 'network', 'ARP scanner'),
('netdiscover', 'network', 'Network discovery tool'),
('sqlmap', 'web', 'SQL injection tool'),
('burpsuite', 'web', 'Web application security testing'),
('nikto', 'web', 'Web server scanner'),
('gobuster', 'web', 'Directory/file brute-forcer'),
('dirb', 'web', 'Web content scanner'),
('wfuzz', 'web', 'Web application fuzzer'),
('ffuf', 'web', 'Fast web fuzzer'),
('hashcat', 'crypto', 'Password recovery tool'),
('john', 'crypto', 'John the Ripper password cracker'),
('gdb', 'pwn', 'GNU debugger'),
('ghidra', 'pwn', 'Reverse engineering framework'),
('radare2', 'pwn', 'Reverse engineering framework')
ON CONFLICT (tool_name) DO NOTHING;

-- ============================================
-- SEED DATA: Invalid Service Names
-- ============================================
INSERT INTO invalid_service_names (service_name, reason, parent_package) VALUES
('netbios', 'Part of Samba package', 'samba'),
('netbios-ns', 'Part of Samba package', 'samba'),
('netbios-ssn', 'Part of Samba package', 'samba'),
('netbios-dgm', 'Part of Samba package', 'samba'),
('cifs', 'Protocol, comes with Samba', 'samba'),
('smb2', 'Protocol, comes with Samba', 'samba'),
('smb3', 'Protocol, comes with Samba', 'samba'),
('echo', 'xinetd service, not a package', 'xinetd'),
('discard', 'xinetd service, not a package', 'xinetd'),
('chargen', 'xinetd service, not a package', 'xinetd')
ON CONFLICT (service_name) DO NOTHING;

-- ============================================
-- SEED DATA: Base Tools by OS Type
-- ============================================
INSERT INTO base_tools_by_os (os_type, package_manager, tools, description) VALUES
('apt-get', 'apt-get', ARRAY['openssh-server', 'sudo', 'vim', 'nano', 'curl', 'wget', 'git', 'net-tools', 'iputils-ping', 'ca-certificates', 'unzip', 'python3', 'python3-pip'], 'Base tools for Debian/Ubuntu'),
('apk', 'apk', ARRAY['openssh', 'sudo', 'vim', 'nano', 'curl', 'wget', 'git', 'net-tools', 'iputils-ping'], 'Base tools for Alpine Linux'),
('dnf', 'dnf', ARRAY['openssh-server', 'sudo', 'vim', 'nano', 'curl', 'wget', 'git', 'net-tools', 'iputils'], 'Base tools for RHEL/CentOS/Rocky'),
('yum', 'yum', ARRAY['openssh-server', 'sudo', 'vim', 'nano', 'curl', 'wget', 'git', 'net-tools', 'iputils'], 'Base tools for RHEL/CentOS (legacy)')
ON CONFLICT (os_type) DO NOTHING;

-- ============================================
-- SEED DATA: Tool Categories
-- ============================================
INSERT INTO tool_categories (tool_name, category, priority) VALUES
-- Network tools
('nmap', 'network', 10),
('masscan', 'network', 9),
('wireshark', 'network', 9),
('tcpdump', 'network', 8),
('netcat-traditional', 'network', 8),
('hping3', 'network', 7),
('arp-scan', 'network', 7),
('netdiscover', 'network', 6),
('traceroute', 'network', 6),
('whois', 'network', 5),
('dnsutils', 'network', 5),
-- Web tools
('burpsuite', 'web', 10),
('sqlmap', 'web', 10),
('nikto', 'web', 9),
('gobuster', 'web', 9),
('dirb', 'web', 8),
('wfuzz', 'web', 8),
('ffuf', 'web', 8),
-- Crypto tools
('hashcat', 'crypto', 10),
('john', 'crypto', 10),
('openssl', 'crypto', 9),
('hashid', 'crypto', 7),
-- PWN tools
('gdb', 'pwn', 10),
('ghidra', 'pwn', 9),
('radare2', 'pwn', 9),
('objdump', 'pwn', 8),
('ltrace', 'pwn', 7),
('strace', 'pwn', 7),
('python3-pwntools', 'pwn', 8)
ON CONFLICT (tool_name, category) DO NOTHING;

-- ============================================
-- SEED DATA: Tool to Package Mappings (Kali)
-- ============================================
INSERT INTO tool_package_mappings (tool_name, package_name, os_type, category) VALUES
-- Web tools
('burpsuite', 'burpsuite', 'kali', 'web'),
('sqlmap', 'sqlmap', 'kali', 'web'),
('nikto', 'nikto', 'kali', 'web'),
('gobuster', 'gobuster', 'kali', 'web'),
('dirb', 'dirb', 'kali', 'web'),
('wfuzz', 'wfuzz', 'kali', 'web'),
('ffuf', 'ffuf', 'kali', 'web'),
-- Network tools
('nmap', 'nmap', 'kali', 'network'),
('masscan', 'masscan', 'kali', 'network'),
('wireshark', 'wireshark', 'kali', 'network'),
('tcpdump', 'tcpdump', 'kali', 'network'),
('netcat', 'netcat-traditional', 'kali', 'network'),
('nc', 'netcat-traditional', 'kali', 'network'),
('hping3', 'hping3', 'kali', 'network'),
('arp-scan', 'arp-scan', 'kali', 'network'),
('netdiscover', 'netdiscover', 'kali', 'network'),
('traceroute', 'traceroute', 'kali', 'network'),
-- Crypto tools
('hashcat', 'hashcat', 'kali', 'crypto'),
('john', 'john', 'kali', 'crypto'),
('openssl', 'openssl', 'kali', 'crypto'),
-- PWN tools
('gdb', 'gdb', 'kali', 'pwn'),
('ghidra', 'ghidra', 'kali', 'pwn'),
('radare2', 'radare2', 'kali', 'pwn'),
('objdump', 'binutils', 'kali', 'pwn')
ON CONFLICT (tool_name, os_type) DO NOTHING;

COMMENT ON TABLE service_package_mappings IS 'Maps service names to package names across different OS types';
COMMENT ON TABLE package_aliases IS 'Maps common package name variations to correct package names';
COMMENT ON TABLE attack_tools IS 'Tools that should only be on attacker machines, never on victims';
COMMENT ON TABLE invalid_service_names IS 'Service/protocol names that are NOT packages';
COMMENT ON TABLE base_tools_by_os IS 'Essential tools installed on all machines by OS type';
COMMENT ON TABLE tool_categories IS 'Maps tools to categories for automatic tool selection';
COMMENT ON TABLE tool_package_mappings IS 'Maps tool names to their package names (primarily for Kali/attacker machines)';

