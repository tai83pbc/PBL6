from flask import Flask, render_template, request
import sqlite3
import os
import time # For time-based SQLi simulation

app = Flask(__name__)
DATABASE = 'database.db'

def init_db():
    if not os.path.exists(DATABASE):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        with open('database.sql', 'r') as f:
            sql_script = f.read()
        cursor.executescript(sql_script)
        conn.commit()
        conn.close()

@app.before_request
def before_request_func():
    init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/xss', methods=['GET'])
def xss():
    query_input = request.args.get('query', '')
    # The vulnerability is in templates/xss.html using | safe
    return render_template('xss.html', query_input=query_input)

@app.route('/sqli', methods=['GET'])
def sqli():
    user_id = request.args.get('id', '1')
    user_info = None
    error_message = None

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # THIS IS THE VULNERABLE SPOT: Direct concatenation of user input into SQL query
    # In a real app, use parameterized queries (e.g., cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,)))
    try:
        # Simulate a delay for time-based SQLi payloads like SLEEP(5)
        # This is a very basic detection; a real DB would execute the actual SLEEP
        if "SLEEP(5)" in user_id.upper() or "WAITFOR DELAY '0:0:5'" in user_id.upper():
            time.sleep(5) 
        
        query = f"SELECT id, username, email FROM users WHERE id = {user_id}"
        app.logger.info(f"Executing SQL query: {query}")
        cursor.execute(query)
        result = cursor.fetchone()
        if result:
            user_info = {
                'id': result[0],
                'username': result[1],
                'email': result[2]
            }
    except sqlite3.Error as e:
        error_message = f"Database Error: {e}"
        app.logger.error(f"SQLi attempt detected or database error: {e}, Query: {query}")
    finally:
        conn.close()

    return render_template('sqli.html', user_id=user_id, user_info=user_info, error_message=error_message)

if __name__ == '__main__':
    # Clean up old database for fresh start on each run (optional)
    if os.path.exists(DATABASE):
        os.remove(DATABASE)
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
