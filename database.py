import sqlite3
from datetime import datetime

# Define the SQLite database filename
DB_NAME = "sentinel_history.db"

# Initialize the database and create the required tables on server startup
def init_db():
    # Establish a connection to the SQLite database
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Create the 'alerts' table if it does not already exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            risk_score TEXT,
            ai_report TEXT
        )
    ''')
    
    # Commit the transaction and close the database connection
    conn.commit()
    conn.close()

# Insert a new security alert record into the database
def save_alert(source_ip, risk_score, ai_report):
    # Establish a connection to the SQLite database
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Generate the current timestamp in 'YYYY-MM-DD HH:MM:SS' format
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Execute the insertion query with parameterized values to prevent SQL injection
    cursor.execute('''
        INSERT INTO alerts (timestamp, source_ip, risk_score, ai_report)
        VALUES (?, ?, ?, ?)
    ''', (timestamp, source_ip, risk_score, ai_report))
    
    # Commit the transaction and close the database connection
    conn.commit()
    conn.close()

# Retrieve all stored alerts from the database to display on the dashboard
def get_all_alerts():
    # Establish a connection to the SQLite database
    conn = sqlite3.connect(DB_NAME)
    
    # Configure the connection to return rows as dictionary-like objects instead of tuples
    conn.row_factory = sqlite3.Row 
    cursor = conn.cursor()
    
    # Execute the query to fetch all alerts, ordered by most recent first (descending ID)
    cursor.execute('SELECT * FROM alerts ORDER BY id DESC')
    
    # Fetch all retrieved rows
    rows = cursor.fetchall()
    
    # Close the database connection
    conn.close()
    
    # Convert the row objects into standard Python dictionaries and return the list
    return [dict(row) for row in rows]