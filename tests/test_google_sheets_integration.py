import pytest
from unittest.mock import MagicMock, patch
from workshops_mcp import workshop_read_instructors, workshop_read_feedback

@pytest.mark.asyncio
async def test_workshop_read_instructors_no_creds():
    with patch('workshops_mcp.get_google_credentials', return_value=None):
        params = {}
        result = await workshop_read_instructors(params)
        assert "error" in result
        assert "auth_url" in result
        assert result["error"] == "Google Sheets not authorized"

@pytest.mark.asyncio
async def test_workshop_read_instructors_success():
    mock_creds = MagicMock()
    mock_values = [
        ["Name", "Interest", "Email"],
        ["John Doe", "Workshops", "john@example.com"],
        ["Jane Smith", "Coding", "jane@example.com"]
    ]
    
    with patch('workshops_mcp.get_google_credentials', return_value=mock_creds):
        with patch('workshops_mcp.build') as mock_build:
            mock_service = mock_build.return_value
            mock_sheet = mock_service.spreadsheets.return_value
            mock_values_get = mock_sheet.values.return_value.get.return_value
            mock_values_get.execute.return_value = {"values": mock_values}
            
            params = {"spreadsheet_id": "test_id", "range_name": "Sheet1!A:C"}
            result = await workshop_read_instructors(params)
            
            assert "instructors" in result
            assert len(result["instructors"]) == 2
            assert result["instructors"][0]["Name"] == "John Doe"
            assert result["instructors"][1]["Email"] == "jane@example.com"

@pytest.mark.asyncio
async def test_workshop_read_feedback_success():
    mock_creds = MagicMock()
    mock_values = [
        ["Workshop Title", "Score", "Comment"],
        ["Advanced Robotics", "5", "Great!"],
        ["Intro to Neuro", "4", "Good"]
    ]
    
    with patch('workshops_mcp.get_google_credentials', return_value=mock_creds):
        with patch('workshops_mcp.build') as mock_build:
            mock_service = mock_build.return_value
            mock_sheet = mock_service.spreadsheets.return_value
            mock_values_get = mock_sheet.values.return_value.get.return_value
            mock_values_get.execute.return_value = {"values": mock_values}
            
            # Test filter by title
            params = {"spreadsheet_id": "test_id", "workshop_title": "Robotics"}
            result = await workshop_read_feedback(params)
            
            assert "feedback" in result
            assert len(result["feedback"]) == 1
            assert result["feedback"][0]["Workshop Title"] == "Advanced Robotics"
