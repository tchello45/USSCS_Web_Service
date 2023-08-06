import sqlite3
import os
import hashlib
path = "DATABASE/"
if not os.path.exists(path):
    ValueError("DATABASE folder not found, please create it and try again.")

def create_main_db():
    conn = sqlite3.connect(path + "APIs.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS APIs ( id INTEGER PRIMARY KEY AUTOINCREMENT, client TEXT, users INTEGER, registration_hash TEXT, login_hash TEXT, enc BOOLEAN DEFAULT FALSE, max_users INTEGER, level INTEGER)''')
    conn.commit()
    conn.close()

def get_level(id_):
    conn = sqlite3.connect(path + "APIs.db")
    c = conn.cursor()
    c.execute('''SELECT * FROM APIs WHERE id=?''', (id_,))
    if c.fetchone() is None:
        conn.close()
        return False
    else:
        c.execute('''SELECT * FROM APIs WHERE id=?''', (id_,))
        level = c.fetchone()[7]
        conn.close()
        return level
def get_max_users(id_):
    conn = sqlite3.connect(path + "APIs.db")
    c = conn.cursor()
    c.execute('''SELECT * FROM APIs WHERE id=?''', (id_,))
    if c.fetchone() is None:
        conn.close()
        return False
    else:
        c.execute('''SELECT * FROM APIs WHERE id=?''', (id_,))
        max_users = c.fetchone()[6]
        conn.close()
        return max_users
def set_max_users(id_, max_users:int):
    conn = sqlite3.connect(path + "APIs.db")
    c = conn.cursor()
    c.execute('''UPDATE APIs SET max_users=? WHERE id=?''', (max_users, id_))
    conn.commit()
    conn.close()
    return True
def set_level(id_, level:int):
    conn = sqlite3.connect(path + "APIs.db")
    c = conn.cursor()
    c.execute('''UPDATE APIs SET level=? WHERE id=?''', (level, id_))
    conn.commit()
    conn.close()
    return True
def add_client(client:str, regsistration_password:str, login_password:str, enc=False, max_users=100, level=0):
    conn = sqlite3.connect(path + "APIs.db")
    c = conn.cursor()
    c.execute('''SELECT * FROM APIs WHERE client=?''', (client,))
    if c.fetchone() is None:
        c.execute('''INSERT INTO APIs (client, users, registration_hash, login_hash, enc, max_users, level) VALUES (?, ?, ?, ?, ?, ?, ?)''', (client, 0, hashlib.sha256(regsistration_password.encode()).hexdigest(), hashlib.sha256(login_password.encode()).hexdigest(), enc, max_users, level))
        conn.commit()
        c.execute('''SELECT * FROM APIs WHERE client=?''', (client,))
        id_ = c.fetchone()[0]
        conn.close()
        os.mkdir(path + "APIs/" + str(id_) + "/")
        return id_
        
    else:
        conn.close()
        return False
def get_id(client:str):
    conn = sqlite3.connect(path + "APIs.db")
    c = conn.cursor()
    c.execute('''SELECT * FROM APIs WHERE client=?''', (client,))
    if c.fetchone() is None:
        conn.close()
        return False
    else:
        c.execute('''SELECT * FROM APIs WHERE client=?''', (client,))
        id_ = c.fetchone()[0]
        conn.close()
        return id_
def get_registration_hash(id_):
    conn = sqlite3.connect(path + "APIs.db")
    c = conn.cursor()
    c.execute('''SELECT * FROM APIs WHERE id=?''', (id_,))
    if c.fetchone() is None:
        conn.close()
        return False
    else:
        c.execute('''SELECT * FROM APIs WHERE id=?''', (id_,))
        registration_hash = c.fetchone()[3]
        conn.close()
        return registration_hash
def get_login_hash(id_):
    conn = sqlite3.connect(path + "APIs.db")
    c = conn.cursor()
    c.execute('''SELECT * FROM APIs WHERE id=?''', (id_,))
    if c.fetchone() is None:
        conn.close()
        return False
    else:
        c.execute('''SELECT * FROM APIs WHERE id=?''', (id_,))
        login_hash = c.fetchone()[4]
        conn.close()
        return login_hash
def get_enc(id_):
    conn = sqlite3.connect(path + "APIs.db")
    c = conn.cursor()
    c.execute('''SELECT * FROM APIs WHERE id=?''', (id_,))
    if c.fetchone() is None:
        conn.close()
        return False
    else:
        c.execute('''SELECT * FROM APIs WHERE id=?''', (id_,))
        enc = c.fetchone()[5]
        conn.close()
        return enc
def get_client(id_):
    conn = sqlite3.connect(path + "APIs.db")
    c = conn.cursor()
    c.execute('''SELECT * FROM APIs WHERE id=?''', (id_,))
    if c.fetchone() is None:
        conn.close()
        return False
    else:
        c.execute('''SELECT * FROM APIs WHERE id=?''', (id_,))
        client = c.fetchone()[1]
        conn.close()
        return client
def get_all_clients():
    conn = sqlite3.connect(path + "APIs.db")
    c = conn.cursor()
    c.execute('''SELECT client FROM APIs''')
    clients = c.fetchall()
    conn.close()
    return clients
