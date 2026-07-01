from fastapi import FastAPI, Depends
import sqlite3

app = FastAPI()

def get_db_connection():
    conn = sqlite3.connect("app_database.db")
    return conn

@app.get("/search-certificates")
def search_certificates(certificate_id: str):
    # SECURE: Using parameterized inputs (?) protects against SQL Injection
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM certificates WHERE id = ?"
    cursor.execute(query, (certificate_id,))
    
    results = cursor.fetchall()
    conn.close()
    return {"results": results}
