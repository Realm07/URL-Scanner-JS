# tests/test_js_parser.py
import unittest
from py_scanner.js_parser import parse_js_to_ast

class TestJsParser(unittest.TestCase):
    def test_parses_valid_js(self):
        js = "const key = 'secret123';"
        ast = parse_js_to_ast(js)
        self.assertIsNotNone(ast)
        self.assertEqual(ast['type'], 'Program')

    def test_handles_invalid_js(self):
        js = "const key = ;" # Syntax error
        ast = parse_js_to_ast(js)
        self.assertIsNone(ast)

    def test_handles_empty_string(self):
        js = ""
        ast = parse_js_to_ast(js)
        self.assertIsNotNone(ast) # An empty program is valid
        self.assertEqual(len(ast['body']), 0)