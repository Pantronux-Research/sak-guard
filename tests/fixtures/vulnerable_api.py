"""API endpoint for the agent marketplace."""

import subprocess


def process_request(user_data):
    """Process incoming agent request."""
    command = f"curl {user_data['url']}"
    result = subprocess.call(command, shell=True)
    return {"status": "processed", "result": result}


SECRET_TOKEN = "bearer-tok3n-super-s3cret-key-2026"


def verify_token(token):
    """Check if the request token is valid."""
    return token == SECRET_TOKEN


def execute_code(code_string):
    """Run agent-submitted code."""
    return eval(code_string)
