import unittest
from unittest.mock import MagicMock, patch
import workshops_mcp
import phpserialize
import json

class TestPolylang(unittest.TestCase):

    def test_php_serialization_roundtrip(self):
        """Test that our serialization matches expectations."""
        # Mapping: {'en': 55, 'sr': 58}
        mapping = {'en': 55, 'sr': 58}
        
        # Sort and serialize
        sorted_map = dict(sorted(mapping.items()))
        bytes_map = {k.encode('utf-8'): v for k, v in sorted_map.items()}
        serialized = phpserialize.dumps(bytes_map).decode('utf-8')
        
        # Verify the PHP string
        # a:2:{s:2:"en";i:55;s:2:"sr";i:58;}
        self.assertIn('s:2:"en";i:55', serialized)
        self.assertIn('s:2:"sr";i:58', serialized)
        
        # Deserialize back
        deserialized = workshops_mcp._deserialize_php(serialized)
        self.assertEqual(deserialized, {'en': '55', 'sr': '58'})

    @patch('workshops_mcp.requests.get')
    def test_polylang_client_discovery(self, mock_get):
        """Test that PolylangClient correctly parses the REST response."""
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {
                "slug": "en",
                "term_props": {
                    "language": {
                        "term_taxonomy_id": 55
                    }
                }
            },
            {
                "slug": "sr",
                "term_props": {
                    "language": {
                        "term_taxonomy_id": 58
                    }
                }
            }
        ]
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        with patch('workshops_mcp.WP_URL', 'https://example.com'):
            # We need to force a re-init because of the singleton
            workshops_mcp._polylang_client = None
            client = workshops_mcp.get_polylang_client()
            
            self.assertIsNotNone(client)
            self.assertEqual(client.get_tt_id('en'), 55)
            self.assertEqual(client.get_tt_id('sr'), 58)

    @patch('workshops_mcp.get_db_connection')
    def test_pll_save_translations_merge(self, mock_conn):
        """Test the merge logic in pll_save_translations."""
        mock_cursor = MagicMock()
        mock_conn.return_value.cursor.return_value = mock_cursor
        
        # Scenario: Post A (id 1, lang 'en') is in group G1
        # Post B (id 2, lang 'sr') is in group G2
        # We want to link them (implicitly merging G1 and G2)
        
        # 1. Fetch existing groups
        # tr.object_id, tt.term_taxonomy_id, tt.description
        mock_cursor.fetchall.return_value = [
            {'object_id': 1, 'term_taxonomy_id': 100, 'description': 'a:1:{s:2:"en";i:1;}'},
            {'object_id': 2, 'term_taxonomy_id': 200, 'description': 'a:1:{s:2:"sr";i:2;}'}
        ]
        
        # Mock term_id for deletion
        mock_cursor.fetchone.return_value = {'term_id': 500}
        
        workshops_mcp.pll_save_translations(mock_cursor, {'en': 1, 'sr': 2})
        
        # Check that one group was updated and the other deleted
        # The code chooses group_tt_ids[0] (which would be 100)
        
        # Verify UPDATE on group 100
        update_call = next((c for c in mock_cursor.execute.call_args_list if c[0][0].startswith("UPDATE wp_term_taxonomy")), None)
        self.assertIsNotNone(update_call)
        self.assertEqual(update_call[0][1][2], 100) # tt_id
        
        # Verify DELETE on group 200
        delete_rel_call = next((c for c in mock_cursor.execute.call_args_list if "DELETE FROM wp_term_relationships WHERE term_taxonomy_id = %s" in c[0][0]), None)
        self.assertIsNotNone(delete_rel_call)
        self.assertEqual(delete_rel_call[0][1], (200,))

if __name__ == '__main__':
    unittest.main()
