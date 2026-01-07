#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MySQL to PostgreSQL Migration Script for Guacamole Database
This script migrates data from MySQL guacamole_db to PostgreSQL guacamole_db
while keeping the databases separate.
"""

import mysql.connector
import psycopg2
from psycopg2.extras import execute_batch
import sys
import os
from typing import Dict, List, Tuple, Any
import argparse
from datetime import datetime

# Fix Windows console encoding
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Table order for migration (respecting foreign key dependencies)
MIGRATION_ORDER = [
    'guacamole_entity',
    'guacamole_connection_group',
    'guacamole_connection',
    'guacamole_user',
    'guacamole_user_group',
    'guacamole_user_group_member',
    'guacamole_sharing_profile',
    'guacamole_connection_parameter',
    'guacamole_sharing_profile_parameter',
    'guacamole_user_attribute',
    'guacamole_user_group_attribute',
    'guacamole_connection_attribute',
    'guacamole_connection_group_attribute',
    'guacamole_sharing_profile_attribute',
    'guacamole_connection_permission',
    'guacamole_connection_group_permission',
    'guacamole_sharing_profile_permission',
    'guacamole_system_permission',
    'guacamole_user_permission',
    'guacamole_user_group_permission',
    'guacamole_connection_history',
    'guacamole_user_history',
    'guacamole_user_password_history',
]

# Tables with binary data (BYTEA in PostgreSQL)
BINARY_TABLES = {
    'guacamole_user': ['password_hash', 'password_salt'],
    'guacamole_user_password_history': ['password_hash', 'password_salt'],
}

# Tables with boolean columns that need conversion (MySQL 0/1 -> PostgreSQL true/false)
BOOLEAN_COLUMNS = {
    'guacamole_connection': ['failover_only'],
    'guacamole_connection_group': ['enable_session_affinity'],
    'guacamole_user': ['disabled', 'expired'],
    'guacamole_user_group': ['disabled'],
}

def connect_mysql(host: str, port: int, user: str, password: str, database: str):
    """Connect to MySQL database"""
    try:
        conn = mysql.connector.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database,
            charset='utf8mb4'
        )
        print(f"[OK] Connected to MySQL: {host}:{port}/{database}")
        return conn
    except mysql.connector.Error as e:
        print(f"[ERROR] MySQL connection error: {e}")
        sys.exit(1)

def connect_postgresql(host: str, port: int, user: str, password: str, database: str):
    """Connect to PostgreSQL database"""
    try:
        conn = psycopg2.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database
        )
        conn.autocommit = False
        print(f"[OK] Connected to PostgreSQL: {host}:{port}/{database}")
        return conn
    except psycopg2.Error as e:
        print(f"[ERROR] PostgreSQL connection error: {e}")
        sys.exit(1)

def get_table_columns(mysql_conn, table_name: str) -> List[str]:
    """Get column names for a table"""
    cursor = mysql_conn.cursor()
    cursor.execute(f"DESCRIBE {table_name}")
    columns = [row[0] for row in cursor.fetchall()]
    cursor.close()
    return columns

def convert_binary_data(data: bytes) -> bytes:
    """Convert MySQL binary data to PostgreSQL BYTEA format"""
    if data is None:
        return None
    return data

def convert_boolean_value(value: Any, column_name: str, table_name: str) -> Any:
    """Convert MySQL boolean (0/1) to PostgreSQL boolean (True/False)"""
    if value is None:
        return None
    
    # Check if this column needs boolean conversion
    if table_name in BOOLEAN_COLUMNS and column_name in BOOLEAN_COLUMNS[table_name]:
        # MySQL stores booleans as TINYINT(1): 0 = False, 1 = True
        if isinstance(value, (int, bool)):
            return bool(value)
        # Handle string representations
        if isinstance(value, str):
            return value.lower() in ('1', 'true', 'yes', 'on')
    
    return value

def migrate_table(mysql_conn, pg_conn, table_name: str, batch_size: int = 1000):
    """Migrate a single table from MySQL to PostgreSQL"""
    print(f"\n[MIGRATING] Table: {table_name}")
    
    mysql_cursor = mysql_conn.cursor()
    pg_cursor = pg_conn.cursor()
    
    try:
        # Get column names
        columns = get_table_columns(mysql_conn, table_name)
        columns_str = ', '.join(columns)
        placeholders = ', '.join(['%s'] * len(columns))
        
        # Count rows
        mysql_cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
        total_rows = mysql_cursor.fetchone()[0]
        print(f"   Found {total_rows} rows")
        
        if total_rows == 0:
            print(f"   [SKIP] Empty table")
            return
        
        # Fetch data
        mysql_cursor.execute(f"SELECT {columns_str} FROM {table_name}")
        
        # Prepare insert statement
        insert_sql = f"INSERT INTO {table_name} ({columns_str}) VALUES ({placeholders})"
        
        # Check if table has binary or boolean columns
        has_binary = table_name in BINARY_TABLES
        binary_columns = BINARY_TABLES.get(table_name, [])
        has_boolean = table_name in BOOLEAN_COLUMNS
        boolean_columns = BOOLEAN_COLUMNS.get(table_name, [])
        
        # Migrate in batches
        rows_migrated = 0
        batch = []
        
        for row in mysql_cursor:
            # Convert data types if needed
            if has_binary or has_boolean:
                row = list(row)
                for i, col in enumerate(columns):
                    # Convert binary data
                    if has_binary and col in binary_columns and row[i] is not None:
                        row[i] = convert_binary_data(row[i])
                    # Convert boolean data
                    if has_boolean and col in boolean_columns:
                        row[i] = convert_boolean_value(row[i], col, table_name)
                row = tuple(row)
            
            batch.append(row)
            
            if len(batch) >= batch_size:
                try:
                    execute_batch(pg_cursor, insert_sql, batch)
                    pg_conn.commit()
                    rows_migrated += len(batch)
                    print(f"   Progress: {rows_migrated}/{total_rows} rows", end='\r')
                    batch = []
                except psycopg2.Error as e:
                    pg_conn.rollback()
                    print(f"\n   [ERROR] Error inserting batch: {e}")
                    raise
        
        # Insert remaining rows
        if batch:
            try:
                execute_batch(pg_cursor, insert_sql, batch)
                pg_conn.commit()
                rows_migrated += len(batch)
            except psycopg2.Error as e:
                pg_conn.rollback()
                print(f"\n   [ERROR] Error inserting final batch: {e}")
                raise
        
        print(f"   [OK] Migrated {rows_migrated}/{total_rows} rows")
        
    except Exception as e:
        print(f"   [ERROR] Error migrating {table_name}: {e}")
        pg_conn.rollback()
        raise
    finally:
        mysql_cursor.close()
        pg_cursor.close()

def reset_sequences(pg_conn):
    """Reset PostgreSQL sequences to match migrated data"""
    print("\n[RESET] Resetting sequences...")
    pg_cursor = pg_conn.cursor()
    
    try:
        # Get all tables with SERIAL columns
        pg_cursor.execute("""
            SELECT table_name, column_name
            FROM information_schema.columns
            WHERE table_schema = 'public'
            AND column_default LIKE 'nextval%'
            AND table_name LIKE 'guacamole_%'
            ORDER BY table_name, column_name
        """)
        
        sequences_reset = 0
        for table_name, column_name in pg_cursor.fetchall():
            try:
                # Get max value from table
                pg_cursor.execute(f"SELECT COALESCE(MAX({column_name}), 0) FROM {table_name}")
                max_val = pg_cursor.fetchone()[0]
                
                if max_val > 0:
                    # Reset sequence
                    sequence_name = f"{table_name}_{column_name}_seq"
                    pg_cursor.execute(f"SELECT setval('{sequence_name}', {max_val}, true)")
                    sequences_reset += 1
            except Exception as e:
                    print(f"   [WARNING] Could not reset sequence for {table_name}.{column_name}: {e}")
        
        pg_conn.commit()
        print(f"   [OK] Reset {sequences_reset} sequences")
        
    except Exception as e:
        print(f"   [ERROR] Error resetting sequences: {e}")
        pg_conn.rollback()
    finally:
        pg_cursor.close()

def verify_migration(mysql_conn, pg_conn):
    """Verify that row counts match between MySQL and PostgreSQL"""
    print("\n[VERIFY] Verifying migration...")
    mysql_cursor = mysql_conn.cursor()
    pg_cursor = pg_conn.cursor()
    
    all_match = True
    
    for table_name in MIGRATION_ORDER:
        try:
            # Count MySQL rows
            mysql_cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            mysql_count = mysql_cursor.fetchone()[0]
            
            # Count PostgreSQL rows
            pg_cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            pg_count = pg_cursor.fetchone()[0]
            
            if mysql_count == pg_count:
                print(f"   [OK] {table_name}: {mysql_count} rows")
            else:
                print(f"   [ERROR] {table_name}: MySQL={mysql_count}, PostgreSQL={pg_count}")
                all_match = False
                
        except Exception as e:
            print(f"   [ERROR] Error verifying {table_name}: {e}")
            all_match = False
    
    mysql_cursor.close()
    pg_cursor.close()
    
    if all_match:
        print("\n[SUCCESS] Migration verification: All tables match!")
    else:
        print("\n[WARNING] Migration verification: Some tables don't match!")
    
    return all_match

def main():
    parser = argparse.ArgumentParser(
        description='Migrate Guacamole database from MySQL to PostgreSQL'
    )
    
    # MySQL connection
    parser.add_argument('--mysql-host', default='localhost', help='MySQL host')
    parser.add_argument('--mysql-port', type=int, default=3307, help='MySQL port')
    parser.add_argument('--mysql-user', default='guacamole_user', help='MySQL user')
    parser.add_argument('--mysql-password', default='guacamole_password_123', help='MySQL password')
    parser.add_argument('--mysql-database', default='guacamole_db', help='MySQL database')
    
    # PostgreSQL connection
    parser.add_argument('--pg-host', default='localhost', help='PostgreSQL host')
    parser.add_argument('--pg-port', type=int, default=5432, help='PostgreSQL port')
    parser.add_argument('--pg-user', default='postgres', help='PostgreSQL user')
    parser.add_argument('--pg-password', required=True, help='PostgreSQL password')
    parser.add_argument('--pg-database', default='guacamole_db', help='PostgreSQL database')
    
    # Options
    parser.add_argument('--skip-verification', action='store_true', help='Skip verification step')
    parser.add_argument('--batch-size', type=int, default=1000, help='Batch size for inserts')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("MySQL to PostgreSQL Migration Tool")
    print("Guacamole Database Migration")
    print("=" * 60)
    print(f"\nSource: MySQL {args.mysql_host}:{args.mysql_port}/{args.mysql_database}")
    print(f"Target: PostgreSQL {args.pg_host}:{args.pg_port}/{args.pg_database}")
    print("\nWARNING: This will migrate data to PostgreSQL.")
    print("   Make sure the PostgreSQL schema is already created!")
    print("   Use: database/guacamole-postgresql-schema.sql")
    
    response = input("\nContinue? (yes/no): ")
    if response.lower() != 'yes':
        print("Migration cancelled.")
        sys.exit(0)
    
    # Connect to databases
    mysql_conn = connect_mysql(
        args.mysql_host, args.mysql_port,
        args.mysql_user, args.mysql_password,
        args.mysql_database
    )
    
    pg_conn = connect_postgresql(
        args.pg_host, args.pg_port,
        args.pg_user, args.pg_password,
        args.pg_database
    )
    
    try:
        # Migrate tables in order
        print("\n" + "=" * 60)
        print("Starting Migration")
        print("=" * 60)
        
        for table_name in MIGRATION_ORDER:
            try:
                migrate_table(mysql_conn, pg_conn, table_name, args.batch_size)
            except Exception as e:
                print(f"\n✗ Migration failed at table {table_name}: {e}")
                sys.exit(1)
        
        # Reset sequences
        reset_sequences(pg_conn)
        
        # Verify migration
        if not args.skip_verification:
            verify_migration(mysql_conn, pg_conn)
        
        print("\n" + "=" * 60)
        print("[SUCCESS] Migration completed successfully!")
        print("=" * 60)
        print("\nNext steps:")
        print("1. Update Guacamole configuration to use PostgreSQL")
        print("2. Update connection strings in your application")
        print("3. Test the Guacamole service")
        print("4. Keep MySQL database as backup until verified")
        
    except Exception as e:
        print(f"\n[ERROR] Migration failed: {e}")
        sys.exit(1)
    finally:
        mysql_conn.close()
        pg_conn.close()
        print("\n[OK] Database connections closed")

if __name__ == '__main__':
    main()

