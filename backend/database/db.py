import psycopg2
import os
import bcrypt

DATABASE_URL = os.environ.get("DATABASE_URL")


def get_connection():
    return psycopg2.connect(DATABASE_URL)


def init_db():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    cur.close()
    conn.close()


def create_user(name, email, password):
    try:
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
            (name, email, hashed)
        )
        conn.commit()
        cur.close()
        conn.close()
        return True
    except psycopg2.errors.UniqueViolation:
        return False


def get_user(email):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, name, email, password FROM users WHERE email = %s", (email,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if row is None:
        return None
    return {"id": row[0], "name": row[1], "email": row[2], "password": row[3]}