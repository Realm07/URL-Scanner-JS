# tests/test_ast_scanner.py
import unittest
import yaml
from py_scanner.js_parser import parse_js_to_ast
from py_scanner.ast_scanner import scan_ast

class TestAstScanner(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Load the configuration once for all tests."""
        # Assuming config.yaml is in the parent directory of the tests folder
        with open("config.yaml", 'r') as f:
            cls.config = yaml.safe_load(f)

    def test_finds_suspicious_variable_name(self):
        js_code = "const myApiKey = 'hfuehf8349hfu34hfu834hf8h34f8h34';"
        ast = parse_js_to_ast(js_code)
        findings = list(scan_ast(ast, self.config))
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['type'], 'Suspicious Variable Name')
        self.assertEqual(findings[0]['variable'], 'myapikey')
        self.assertEqual(findings[0]['value'], 'hfuehf8349hfu34hfu834hf8h34f8h34')

    def test_ignores_short_secret(self):
        js_code = "const short_key = 'short';"
        ast = parse_js_to_ast(js_code)
        findings = list(scan_ast(ast, self.config))
        self.assertEqual(len(findings), 0)

    def test_finds_suspicious_property_name(self):
        js_code = "app.config.clientSecret = 'super_long_and_secretive_client_key_string';"
        ast = parse_js_to_ast(js_code)
        findings = list(scan_ast(ast, self.config))
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['type'], 'Suspicious Property Name')
        self.assertEqual(findings[0]['property'], 'clientsecret')
        self.assertEqual(findings[0]['value'], 'super_long_and_secretive_client_key_string')

    def test_no_findings_in_clean_code(self):
        js_code = "const x = 10; function add(a, b) { return a + b; }"
        ast = parse_js_to_ast(js_code)
        findings = list(scan_ast(ast, self.config))
        self.assertEqual(len(findings), 0)

# To run the tests from your root project directory:
# python -m unittest discover tests