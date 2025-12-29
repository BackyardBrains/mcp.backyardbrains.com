import unittest
from unittest.mock import MagicMock
import workshops_mcp

class TestSlugManagement(unittest.TestCase):

    def test_transliterate_serbian(self):
        """Test that Serbian characters are correctly transliterated."""
        self.assertEqual(workshops_mcp.transliterate_serbian("čćžšđ"), "cczsdj")
        self.assertEqual(workshops_mcp.transliterate_serbian("ČĆŽŠĐ"), "CCZSDj")
        self.assertEqual(workshops_mcp.transliterate_serbian("абвгдђежзијклљмнњопрстћуфхцчџш"), "abvgddjezzijklljmnnjoprstcufhccdzs")
        self.assertEqual(workshops_mcp.transliterate_serbian("АБВГДЂЕЖЗИЈКЛЉМНЊОПРСТЋУФХЦЧЏШ"), "ABVGDDjEZZIJKLLjMNNjOPRSTCUFHCCDzS") 

    def test_generate_slug_basic(self):
        """Test basic slug generation."""
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None # No duplicates
        
        slug = workshops_mcp.generate_unique_slug("Workshop Title / 2025", mock_cursor)
        self.assertEqual(slug, "workshop-title-2025")

    def test_generate_slug_manual(self):
        """Test manual slug override."""
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        
        slug = workshops_mcp.generate_unique_slug("Ignore Title", mock_cursor, manual_slug="custom-slug")
        self.assertEqual(slug, "custom-slug")

    def test_generate_slug_manual_unsanitized(self):
        """Test manual slug override with unsanitized input."""
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        
        slug = workshops_mcp.generate_unique_slug("Ignore Title", mock_cursor, manual_slug="Custom Slug & More!")
        self.assertEqual(slug, "custom-slug-more")

    def test_generate_slug_serbian(self):
        """Test slug generation with Serbian title."""
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        
        # Latin with diacritics
        slug = workshops_mcp.generate_unique_slug("Radionica u Beogradu (čćžšđ)", mock_cursor)
        self.assertEqual(slug, "radionica-u-beogradu-cczsdj")
        
        # Cyrillic
        slug = workshops_mcp.generate_unique_slug("Радионица у Београду", mock_cursor)
        self.assertEqual(slug, "radionica-u-beogradu")

    def test_generate_slug_collision(self):
        """Test slug collision handling."""
        mock_cursor = MagicMock()
        # First call returns ID 123 (duplicate), second call returns None (unique)
        mock_cursor.fetchone.side_effect = [{'ID': 123}, None]
        
        slug = workshops_mcp.generate_unique_slug("Collision", mock_cursor)
        self.assertEqual(slug, "collision-2")
        self.assertEqual(mock_cursor.execute.call_count, 2)

    def test_generate_slug_multiple_collisions(self):
        """Test multiple slug collisions."""
        mock_cursor = MagicMock()
        # Returns duplicates for 'collision' and 'collision-2', then unique for 'collision-3'
        mock_cursor.fetchone.side_effect = [{'ID': 123}, {'ID': 124}, None]
        
        slug = workshops_mcp.generate_unique_slug("Collision", mock_cursor)
        self.assertEqual(slug, "collision-3")
        self.assertEqual(mock_cursor.execute.call_count, 3)

    def test_generate_slug_same_id_no_collision(self):
        """Test that updating the same post doesn't count as a collision."""
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None # Should return None because we exclude current_id in SQL
        
        slug = workshops_mcp.generate_unique_slug("Collision", mock_cursor, current_id=123)
        self.assertEqual(slug, "collision")
        
        sql, params = mock_cursor.execute.call_args[0]
        self.assertIn("AND ID != %s", sql)
        self.assertIn(123, params)

if __name__ == '__main__':
    unittest.main()
