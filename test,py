import sqlite3

DATABASE = 'Secure_Chatting_Application_DB.db'

conn = sqlite3.connect(DATABASE)
cursor = conn.cursor()
cursor.execute("SELECT username, password FROM users")
users = cursor.fetchall()
for user in users:
    print(f"Username: {user[0]}, Password Hash: {user[1]}")
conn.close()
