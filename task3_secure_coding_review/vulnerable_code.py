from fastapi import FastAPI, Depends
import sqlite3

app = FastAPI()

def get_db_connection():
    conn = sqlite3.connect("app_database.db")
    return conn

@app.get("/search-certificates")
def search_certificates(certificate_id: str):
    # CRITICAL VULNERABILITY: Direct string formatting allows SQL Injection (SQLi)
    # An attacker could input: ' OR '1'='1 to view all records
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = f"SELECT * FROM certificates WHERE id = '{certificate_id}'"
    cursor.execute(query)
    
    results = cursor.fetchall()
    conn.close()
    return {"results": results}
