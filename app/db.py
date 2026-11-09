import sqlite3

_conn = sqlite3.connect(":memory:", check_same_thread=False)


def init_db():
    _conn.executescript(
        """
        DROP TABLE IF EXISTS users;
        CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT);
        INSERT INTO users (name, email) VALUES
            ('ana', 'ana@example.com'),
            ('beto', 'beto@example.com');
        """
    )


def get_conn():
    return _conn
