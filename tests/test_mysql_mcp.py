import unittest
from unittest.mock import MagicMock, patch
import mysql_mcp
from datetime import datetime

class TestMySQLMCP(unittest.TestCase):
    def test_deserialize_php_string(self):
        # Simple string
        val = 's:5:"hello";'
        self.assertEqual(mysql_mcp._deserialize_php(val), b'hello')

    def test_deserialize_php_array(self):
        # Serialized array: a:1:{s:4:"name";s:4:"gage";}
        val = 'a:1:{s:4:"name";s:4:"gage";}'
        expected = {'name': 'gage'}
        self.assertEqual(mysql_mcp._deserialize_php(val), expected)

    def test_deserialize_php_non_serialized(self):
        val = 'plain text'
        self.assertEqual(mysql_mcp._deserialize_php(val), 'plain text')

    @patch('mysql_mcp.get_db_connection')
    def test_get_forms(self, mock_conn):
        mock_cursor = MagicMock()
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_cursor.fetchall.return_value = [{'id': 1, 'name': 'Form 1'}]
        
        result = mysql_mcp.get_forms()
        self.assertEqual(result, [{'id': 1, 'name': 'Form 1'}])
        mock_cursor.execute.assert_called_with("SELECT ID as id, post_title as name FROM wp_posts WHERE post_type = 'forminator_forms'")

    @patch('mysql_mcp.get_db_connection')
    def test_get_entries(self, mock_conn):
        mock_cursor = MagicMock()
        mock_conn.return_value.cursor.return_value = mock_cursor
        
        # Mock data for entries and meta
        dt = datetime(2023, 1, 1, 12, 0, 0)
        mock_cursor.fetchall.return_value = [
            {'entry_id': 101, 'date_created': dt, 'meta_key': 'text-1', 'meta_value': 'value1'},
            {'entry_id': 101, 'date_created': dt, 'meta_key': 'name-1', 'meta_value': 'a:1:{s:4:"name";s:4:"gage";}'}
        ]
        
        result = mysql_mcp.get_entries(1)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['entry_id'], 101)
        self.assertEqual(result[0]['text-1'], 'value1')
        self.assertEqual(result[0]['name-1_name'], 'gage')
        self.assertEqual(result[0]['date_created'], '2023-01-01T12:00:00')

    @patch('mysql_mcp.get_db_connection')
    def test_execute_query(self, mock_conn):
        mock_cursor = MagicMock()
        mock_conn.return_value.cursor.return_value = mock_cursor
        mock_cursor.fetchall.return_value = [{'val': 1}]
        
        result = mysql_mcp.execute_query("SELECT 1")
        self.assertEqual(result, [{'val': 1}])
        mock_cursor.execute.assert_called_with("SELECT 1", None)

if __name__ == '__main__':
    unittest.main()
