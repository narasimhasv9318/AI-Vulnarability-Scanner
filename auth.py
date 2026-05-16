# HARDCODED CREDENTIALS

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"


def authenticate(username, password):

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return True

    return False
