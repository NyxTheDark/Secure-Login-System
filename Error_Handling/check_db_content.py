#!/usr/bin/env python3

import sqlite3
import os

def check_database_content():
    db_path = "instance/user_auth.db"
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # List all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        print("Tables in database:")
        for table in tables:
            print(f"- {table[0]}")
        
        if tables:
            for table in tables:
                table_name = table[0]
                print(f"\nTable: {table_name}")
                cursor.execute(f"SELECT * FROM {table_name};")
                rows = cursor.fetchall()
                print(f"Rows: {len(rows)}")
                
                # Get column names
                cursor.execute(f"PRAGMA table_info({table_name});")
                columns = cursor.fetchall()
                col_names = [col[1] for col in columns]
                print(f"Columns: {col_names}")
                
                # Show some data
                if rows:
                    print("Sample data:")
                    for i, row in enumerate(rows[:3]):  # Show first 3 rows
                        print(f"  Row {i+1}: {row}")
        else:
            print("No tables found in database!")
        
        conn.close()
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_database_content()
