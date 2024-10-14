import unittest
from unittest.mock import patch, MagicMock
import json
import sqlite3
from c4_pro.main.views import save_data_to_db
class TestSaveDataToDb(unittest.TestCase):
    @patch('sqlite3.connect')
    def test_save_data_to_db_with_valid_data(self, mock_connect):
        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_db
        mock_db.cursor.return_value = mock_cursor

        method = 'GET'
        url = '/test'
        headers = {'Content-Type': 'application/json'}

        save_data_to_db(method, url, headers)

        mock_connect.assert_called_once_with('db.sqlite3')
        mock_db.cursor.assert_called_once()
        mock_cursor.execute.assert_called_once_with(
            "INSERT INTO main_packetbaseinfo (method, url, headers) VALUES (?, ?, ?)",
            (method, url, json.dumps(headers))
        )
        mock_db.commit.assert_called_once()
        mock_db.close.assert_called_once()

    @patch('sqlite3.connect')
    def test_save_data_to_db_with_empty_data(self, mock_connect):
        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_db
        mock_db.cursor.return_value = mock_cursor

        method = ''
        url = ''
        headers = {}

        save_data_to_db(method, url, headers)

        mock_connect.assert_called_once_with('db.sqlite3')
        mock_db.cursor.assert_called_once()
        mock_cursor.execute.assert_called_once_with(
            "INSERT INTO main_packetbaseinfo (method, url, headers) VALUES (?, ?, ?)",
            (method, url, json.dumps(headers))
        )
        mock_db.commit.assert_called_once()
        mock_db.close.assert_called_once()

    @patch('sqlite3.connect')
    def test_save_data_to_db_with_database_error(self, mock_connect):
        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_db
        mock_db.cursor.return_value = mock_cursor
        mock_cursor.execute.side_effect = sqlite3.OperationalError

        method = 'GET'
        url = '/test'
        headers = {'Content-Type': 'application/json'}

        try:
            save_data_to_db(method, url, headers)
        except sqlite3.OperationalError:
            pass

        mock_connect.assert_called_once_with('db.sqlite3')
        mock_db.cursor.assert_called_once()
        mock_cursor.execute.assert_called_once_with(
            "INSERT INTO main_packetbaseinfo (method, url, headers) VALUES (?, ?, ?)",
            (method, url, json.dumps(headers))
        )
        mock_db.commit.assert_not_called()
        mock_db.close.assert_called_once()

if __name__ == '__main__':
    unittest.main()