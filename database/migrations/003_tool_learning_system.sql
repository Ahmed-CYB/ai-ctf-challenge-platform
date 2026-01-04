-- Tool Learning System Schema
-- Self-learning database that discovers correct tool installation methods

-- Main tools catalog
CREATE TABLE IF NOT EXISTS ctf_tools (
    id SERIAL PRIMARY KEY,
    tool_name VARCHAR(100) UNIQUE NOT NULL,
    display_name VARCHAR(200),
    description TEXT,
    category VARCHAR(50),  -- forensics, web, network, crypto, pwn
    official_docs_url VARCHAR(500),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    learned_from VARCHAR(100)  -- 'trial', 'readme', 'manual', 'ai'
);

-- Verified installation methods (only successful ones)
CREATE TABLE IF NOT EXISTS tool_installation_methods (
    id SERIAL PRIMARY KEY,
    tool_id INTEGER REFERENCES ctf_tools(id) ON DELETE CASCADE,
    method VARCHAR(50) NOT NULL,  -- 'apt', 'pip', 'gem', 'git', 'cargo', 'npm'
    package_name VARCHAR(200),
    install_command TEXT NOT NULL,
    post_install_verify_command VARCHAR(500),  -- Command to verify installation
    requires_breakage BOOLEAN DEFAULT FALSE,
    requires_sudo BOOLEAN DEFAULT TRUE,
    priority INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    avg_install_time_ms INTEGER,
    kali_version VARCHAR(50),
    last_successful_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(tool_id, method, package_name)
);

-- Tool aliases (e.g., strings → binutils)
CREATE TABLE IF NOT EXISTS tool_aliases (
    id SERIAL PRIMARY KEY,
    alias VARCHAR(100) NOT NULL UNIQUE,
    tool_id INTEGER REFERENCES ctf_tools(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Installation attempt logs (both success and failure)
CREATE TABLE IF NOT EXISTS tool_installation_logs (
    id SERIAL PRIMARY KEY,
    tool_name VARCHAR(100) NOT NULL,
    method VARCHAR(50),
    command_attempted TEXT,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    stdout TEXT,
    stderr TEXT,
    exit_code INTEGER,
    execution_time_ms INTEGER,
    kali_version VARCHAR(50),
    docker_image VARCHAR(200),
    challenge_name VARCHAR(200),
    attempted_at TIMESTAMP DEFAULT NOW()
);

-- Learning queue (tools that need installation method discovery)
CREATE TABLE IF NOT EXISTS tool_learning_queue (
    id SERIAL PRIMARY KEY,
    tool_name VARCHAR(100) NOT NULL,
    category VARCHAR(50),
    priority INTEGER DEFAULT 0,
    attempts INTEGER DEFAULT 0,
    last_error TEXT,
    status VARCHAR(50) DEFAULT 'pending',  -- pending, in_progress, learned, failed
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Tool dependencies
CREATE TABLE IF NOT EXISTS tool_dependencies (
    id SERIAL PRIMARY KEY,
    tool_id INTEGER REFERENCES ctf_tools(id) ON DELETE CASCADE,
    depends_on_tool_id INTEGER REFERENCES ctf_tools(id) ON DELETE CASCADE,
    dependency_type VARCHAR(50) DEFAULT 'required',  -- required, optional, recommended
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(tool_id, depends_on_tool_id)
);

-- README/documentation cache for learning
CREATE TABLE IF NOT EXISTS tool_documentation_cache (
    id SERIAL PRIMARY KEY,
    tool_name VARCHAR(100) NOT NULL,
    source_type VARCHAR(50),  -- 'readme', 'official_docs', 'github', 'kali_docs'
    source_url VARCHAR(500),
    content TEXT,
    extracted_install_commands TEXT[],
    fetched_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(tool_name, source_type)
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_tools_category ON ctf_tools(category);
CREATE INDEX IF NOT EXISTS idx_tools_name ON ctf_tools(tool_name);
CREATE INDEX IF NOT EXISTS idx_aliases_alias ON tool_aliases(alias);
CREATE INDEX IF NOT EXISTS idx_methods_tool ON tool_installation_methods(tool_id);
CREATE INDEX IF NOT EXISTS idx_methods_priority ON tool_installation_methods(priority DESC);
CREATE INDEX IF NOT EXISTS idx_logs_tool ON tool_installation_logs(tool_name);
CREATE INDEX IF NOT EXISTS idx_logs_success ON tool_installation_logs(success);
CREATE INDEX IF NOT EXISTS idx_queue_status ON tool_learning_queue(status);

-- Function to update tool success/failure counts
CREATE OR REPLACE FUNCTION update_method_stats()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.success = TRUE THEN
        UPDATE tool_installation_methods
        SET success_count = success_count + 1,
            last_successful_at = NEW.attempted_at
        WHERE tool_id = (SELECT id FROM ctf_tools WHERE tool_name = NEW.tool_name)
          AND install_command = NEW.command_attempted;
    ELSE
        UPDATE tool_installation_methods
        SET failure_count = failure_count + 1
        WHERE tool_id = (SELECT id FROM ctf_tools WHERE tool_name = NEW.tool_name)
          AND install_command = NEW.command_attempted;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_method_stats
AFTER INSERT ON tool_installation_logs
FOR EACH ROW
EXECUTE FUNCTION update_method_stats();

-- Seed initial known tools
INSERT INTO ctf_tools (tool_name, display_name, category, learned_from) VALUES
('nmap', 'Network Mapper', 'network', 'manual'),
('binutils', 'GNU Binary Utilities', 'forensics', 'manual'),
('python3-pip', 'Python Package Installer', 'misc', 'manual'),
('openssh-server', 'OpenSSH Server', 'misc', 'manual')
ON CONFLICT (tool_name) DO NOTHING;

-- Seed known installation methods
INSERT INTO tool_installation_methods (tool_id, method, package_name, install_command, priority) VALUES
((SELECT id FROM ctf_tools WHERE tool_name = 'nmap'), 'apt', 'nmap', 'apt-get install -y nmap', 1),
((SELECT id FROM ctf_tools WHERE tool_name = 'binutils'), 'apt', 'binutils', 'apt-get install -y binutils', 1),
((SELECT id FROM ctf_tools WHERE tool_name = 'python3-pip'), 'apt', 'python3-pip', 'apt-get install -y python3-pip', 1),
((SELECT id FROM ctf_tools WHERE tool_name = 'openssh-server'), 'apt', 'openssh-server', 'apt-get install -y openssh-server', 1)
ON CONFLICT (tool_id, method, package_name) DO NOTHING;

-- Seed common aliases
INSERT INTO tool_aliases (alias, tool_id) VALUES
('strings', (SELECT id FROM ctf_tools WHERE tool_name = 'binutils')),
('objdump', (SELECT id FROM ctf_tools WHERE tool_name = 'binutils')),
('pip', (SELECT id FROM ctf_tools WHERE tool_name = 'python3-pip')),
('pip3', (SELECT id FROM ctf_tools WHERE tool_name = 'python3-pip'))
ON CONFLICT (alias) DO NOTHING;

COMMENT ON TABLE ctf_tools IS 'Master catalog of CTF tools with verified installation methods';
COMMENT ON TABLE tool_installation_methods IS 'Successful installation methods discovered through learning';
COMMENT ON TABLE tool_installation_logs IS 'Complete history of all installation attempts for analysis';
COMMENT ON TABLE tool_learning_queue IS 'Queue of tools waiting to have installation methods discovered';
COMMENT ON TABLE tool_documentation_cache IS 'Cached documentation for extracting installation commands';
