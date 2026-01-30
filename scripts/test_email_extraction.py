# Mock FastAPI before importing auth
import sys
import os
from unittest.mock import MagicMock
sys.modules["fastapi"] = MagicMock()
sys.modules["fastapi.security"] = MagicMock()
sys.modules["httpx"] = MagicMock()

# Add the project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from auth import extract_email

def test_extraction():
    test_cases = [
        {
            "name": "Standard email claim",
            "payload": {"email": "gagegreg@backyardbrains.com", "sub": "auth0|123"},
            "expected": "gagegreg@backyardbrains.com"
        },
        {
            "name": "Namespaced email claim",
            "payload": {"https://mcp.backyardbrains.com/email": "gagegreg@backyardbrains.com", "sub": "auth0|123"},
            "expected": "gagegreg@backyardbrains.com"
        },
        {
            "name": "Fallback unique_name",
            "payload": {"unique_name": "gagegreg@backyardbrains.com", "sub": "auth0|123"},
            "expected": "gagegreg@backyardbrains.com"
        },
        {
            "name": "Fallback preferred_username",
            "payload": {"preferred_username": "gagegreg@backyardbrains.com", "sub": "auth0|123"},
            "expected": "gagegreg@backyardbrains.com"
        },
        {
            "name": "Missing email entirely",
            "payload": {"sub": "auth0|123", "name": "Greg Gage"},
            "expected": None
        },
        {
            "name": "Standard over fallback",
            "payload": {
                "email": "correct@example.com",
                "unique_name": "wrong@example.com",
                "https://mcp.backyardbrains.com/email": "also_wrong@example.com"
            },
            "expected": "correct@example.com"
        }
    ]

    for case in test_cases:
        result = extract_email(case["payload"])
        if result == case["expected"]:
            print(f"✅ PASS: {case['name']}")
        else:
            print(f"❌ FAIL: {case['name']} | Expected: {case['expected']} | Got: {result}")

if __name__ == "__main__":
    test_extraction()
