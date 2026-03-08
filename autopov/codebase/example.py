"""
Example vulnerable code for testing AutoPoV
Contains intentional SQL injection vulnerability (CWE-89)
"""

import sqlite3


def get_user_unsafe(username):
    """
    Vulnerable function - SQL injection
    CWE-89: Improper Neutralization of Special Elements in SQL Command
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABLE: String concatenation in SQL query
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    
    result = cursor.fetchone()
    conn.close()
    return result


def get_user_safe(username):
    """
    Safe function - uses parameterized query
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # SAFE: Parameterized query
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    
    result = cursor.fetchone()
    conn.close()
    return result


def process_input(user_input):
    """
    Another vulnerable function
    """
    # This should be flagged as potentially dangerous
    return get_user_unsafe(user_input)


if __name__ == "__main__":
    # Test with malicious input
    # This would inject: ' OR '1'='1
    malicious = "' OR '1'='1"
    result = get_user_unsafe(malicious)
    print(f"Result: {result}")
