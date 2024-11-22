import sqlite3

DATABASE = 'Secure_Chatting_Application_DB.db'

conn = sqlite3.connect(DATABASE)
conn.close()
