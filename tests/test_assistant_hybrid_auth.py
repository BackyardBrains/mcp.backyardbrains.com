import pytest
from unittest.mock import MagicMock, patch
import os
import json

# Setup environment for testing
os.environ["ASSISTANT_SERVICE_ACCOUNT_FILE"] = "fake_sa.json"
os.environ["ASSISTANT_USERS_CONFIG_PATH"] = "fake_users.json"
os.environ["TOKEN_ENC_KEY"] = "I98vhCpLWbUA1uRhPnNbhAZ3uJhRhIx565lCzSWI2Go="

from assistant_mcp import AssistantGoogleClient

@pytest.fixture
def mock_config():
    config = {
        "users": {
            "test@example.com": {
                "name": "Test User",
                "enabled": True,
                "root_folder_id": "folder_123"
            }
        }
    }
    with patch("assistant_mcp.get_user_config", return_value=config["users"]["test@example.com"]):
        yield config

@pytest.fixture
def mock_sa_exists():
    with patch("os.path.exists", side_effect=lambda p: p == "fake_sa.json"):
        yield

@pytest.mark.asyncio
async def test_hybrid_auth_fallback_to_sa(mock_config, mock_sa_exists):
    # Mock SA credentials
    mock_sa = MagicMock()
    
    with patch("google.oauth2.service_account.Credentials.from_service_account_file", return_value=mock_sa):
        with patch("assistant_mcp.get_user_tokens", return_value=None):
            client = AssistantGoogleClient("test@example.com")
            
            # SA should be loaded
            assert client.sa_creds == mock_sa
            assert client.user_creds is None
            assert client.effective_creds == mock_sa
            
            # Drive should use SA
            with patch("assistant_mcp.build") as mock_build:
                client.drive
                mock_build.assert_called_with('drive', 'v3', credentials=mock_sa)
                
            # Gmail should raise ValueError with login link
            with pytest.raises(ValueError) as exc:
                client.gmail
            assert "/assistant/google/login" in str(exc.value)

@pytest.mark.asyncio
async def test_hybrid_auth_prioritize_user_tokens(mock_config, mock_sa_exists):
    # Mock SA and User credentials
    mock_sa = MagicMock()
    mock_user = MagicMock()
    mock_user.expired = False
    
    with patch("google.oauth2.service_account.Credentials.from_service_account_file", return_value=mock_sa):
        with patch("assistant_mcp.get_user_tokens", return_value={"token": "fake"}):
            with patch("google.oauth2.credentials.Credentials.from_authorized_user_info", return_value=mock_user):
                client = AssistantGoogleClient("test@example.com")
                
                # Both should be loaded
                assert client.sa_creds == mock_sa
                assert client.user_creds == mock_user
                assert client.effective_creds == mock_user # User prioritizes
                
                # Drive should use User creds
                with patch("assistant_mcp.build") as mock_build:
                    client.drive
                    mock_build.assert_called_with('drive', 'v3', credentials=mock_user)
                    
                # Gmail should work with User creds
                with patch("assistant_mcp.build") as mock_build:
                    client.gmail
                    mock_build.assert_called_with('gmail', 'v1', credentials=mock_user)
