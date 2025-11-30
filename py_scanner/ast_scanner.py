# py_scanner/ast_scanner.py

import re
from pathlib import Path
from typing import Iterator, List
from urllib.parse import urlparse, parse_qs
from .utils import shannon_entropy
from .pattern_loader import load_chromium_patterns

# --- global cache for chromium patterns ---
CHROMIUM_RULES: List[dict] = []

# this regex is a monster. it's designed to catch generic "key = value" assignments
# across a wide variety of formats (yaml, json, code assignments, etc).
# we use this as a catch-all for things that don't match specific vendor patterns.
GENERIC_ASSIGNMENT_REGEX = re.compile(
    r'(?i)((access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .\-,]{0,25})\s*(=|>|:=|\|\|:|<=|=>|:)\s*.{0,5}[\'"]([0-9a-zA-Z\-_=]{8,64})[\'"]'
)

def initialize_chromium_rules(json_path: str):
    """
    loads the chromium autofill regexes into memory.
    we do this once at startup so we don't hit the disk for every single file.
    """
    global CHROMIUM_RULES
    path_obj = Path(json_path)
    if path_obj.exists():
        CHROMIUM_RULES = load_chromium_patterns(path_obj)
        print(f"[INFO] Loaded {len(CHROMIUM_RULES)} Chromium autofill patterns.")
    else:
        print(f"[WARN] Chromium patterns file not found at {json_path}")

# --- helper functions ---

def _get_line_number(node_or_comment: dict) -> int:
    """
    extracting line numbers from esprima nodes is surprisingly annoying.
    the structure varies depending on the node type, so we wrap it here.
    """
    if not isinstance(node_or_comment, dict):
        return 0
    loc = node_or_comment.get('loc')
    if loc and isinstance(loc, dict):
        return loc.get('start', {}).get('line', 0)
    if hasattr(loc, 'start'):
        return getattr(loc.start, 'line', 0)
    return 0

# --- rule 1: chromium pattern checker ---

def _check_chromium_match(text: str, line_num: int, context_type: str):
    """
    checks if a string matches any of the chromium autofill patterns.
    these are great because they're battle-tested by google to find pii fields.
    """
    if not text or len(text) < 3:
        return None
    
    for rule in CHROMIUM_RULES:
        if rule['regex'].search(text):
            return {
                "type": "Potential PII (Autofill Match)",
                "details": f"Matched '{rule['field_type']}' in {context_type}: '{text[:50]}...'",
                "line": line_num,
                "raw_match": text[:100], 
                "pattern_category": rule['field_type']
            }
    return None

def _check_chromium_in_node(node: dict, config: dict):
    """
    applies the chromium rules to specific ast nodes.
    we don't just scan everything because that would be too noisy.
    """
    
    # 1. check variable names (const homeAddress = ...)
    # this is high signal. if a dev explicitly names a variable "homeAddress",
    # they probably mean it.
    if node.get('type') == 'VariableDeclarator':
        var_name = node.get('id', {}).get('name', '')
        return _check_chromium_match(
            var_name, 
            _get_line_number(node), 
            "Variable Name"
        )

    # 2. check property names (user.creditCardNumber = ...)
    # also high signal. object properties are usually very descriptive.
    if node.get('type') == 'Property':
        key_node = node.get('key', {})
        prop_name = key_node.get('name') or key_node.get('value')
        if isinstance(prop_name, str):
            return _check_chromium_match(
                prop_name, 
                _get_line_number(node), 
                "Property Key"
            )
    
    return None

def scan_raw_text(script_code: str, config: dict) -> Iterator[dict]:
    """
    fallback scanner that treats the code as a giant string.
    we use this when the ast parser fails (e.g. on minified code or weird jsx).
    it's dumber but more robust.
    """
    lines = script_code.split('\n')
    
    for i, line in enumerate(lines):
        line_num = i + 1
        
        # 1. check pii (regex) - keep this
        pii = _check_pii(
            line, 
            line_num, 
            "Raw Text", 
            config
        )
        if pii: 
            yield pii
        
        # 2. check vendor patterns (regex) - keep this
        for rule in config['patterns'].get('vendor_regexes', []):
            if re.search(rule['pattern'], line):
                yield {
                    "type": f"Vendor Secret: {rule['name']}",
                    "details": f"Found in Raw Text",
                    "line": line_num
                }
                
        # 3. generic assignment check - keep this
        match = GENERIC_ASSIGNMENT_REGEX.search(line)
        if match:
            key = match.group(1)
            val = match.group(3)
            # entropy check to filter out false positives like "api_key = 'placeholder'"
            if len(val) > 8 and shannon_entropy(val) > 3.5:
                yield {
                    "type": "Suspicious Assignment (Raw Regex)",
                    "details": f"{key} = {val}",
                    "line": line_num
                }

# --- rule 2: config-based pii checker ---

def _check_pii(text_value: str, line_num: int, source_type: str, config: dict):
    """
    checks a string against our custom pii regexes defined in config.yaml.
    """
    if not text_value or not isinstance(text_value, str):
        return None
        
    # ignore list - bail out early for known false positives
    for ignore_val in config['patterns'].get('pii_ignore_list', []):
        if ignore_val in text_value:
            return None

    # run the regex gauntlet
    for pii_rule in config['patterns'].get('pii_regexes', []):
        try:
            matches = re.findall(pii_rule['pattern'], text_value)
            for match in matches:
                if isinstance(match, tuple):
                    match_str = "-".join(match)
                else:
                    match_str = match
                
                # tiny matches are almost always noise
                if len(match_str) < 5:
                    continue

                return {
                    "type": f"Potential PII ({pii_rule['name']})",
                    "details": f"Found in {source_type}: '{match_str}'",
                    "line": line_num
                }
        except re.error:
            continue
    return None

# --- rule 3: secret & logic checks ---

def _check_suspicious_variable(node: dict, config: dict):
    if node.get('type') == 'VariableDeclarator':
        var_name = node.get('id', {}).get('name', '').lower()
        # check if the variable name sounds like a secret (e.g. "api_key", "password")
        if any(keyword in var_name for keyword in config['patterns']['suspicious_variable_names']):
            init_node = node.get('init', {})
            # and check if it's assigned a string literal
            if init_node.get('type') == 'Literal':
                value = init_node.get('value', '')
                if isinstance(value, str) and len(value) >= config['patterns']['min_secret_length']:
                    return {
                        "type": "Suspicious Variable Name",
                        "details": f"Variable '{var_name}' = '{value[:100]}...'",
                        "line": _get_line_number(node)
                    }
    return None

def _check_suspicious_property(node: dict, config: dict):
    if node.get('type') == 'AssignmentExpression':
        left_node = node.get('left', {})
        if left_node.get('type') == 'MemberExpression':
            prop_name = left_node.get('property', {}).get('name', '').lower()
            # same logic as variables, but for object properties (e.g. config.apiKey = "...")
            if any(keyword.lower() in prop_name for keyword in config['patterns']['suspicious_property_names']):
                right_node = node.get('right', {})
                if right_node.get('type') == 'Literal':
                    value = right_node.get('value', '')
                    if isinstance(value, str) and len(value) >= config['patterns']['min_secret_length']:
                        return {
                            "type": "Suspicious Property Name",
                            "details": f"Property '{prop_name}' = '{value[:100]}...'",
                            "line": _get_line_number(node)
                        }
    return None

def _check_api_endpoint(node: dict, config: dict):
    """
    scans for hardcoded api routes. we have to be careful here because
    file paths often look like api endpoints, leading to noise.
    """
    if node.get('type') == 'Literal' and isinstance(node.get('value'), str):
        literal_value = node['value']
        
        # first, run the noise filter. there are libraries (like three.js) that
        # contain thousands of strings that look suspicious but are harmless.
        if any(literal_value.strip().startswith(prefix) for prefix in config['patterns']['ignore_prefixes']):
            return None
            
        # ignore common file extensions. if it ends in .js or .css, it's probably just an import.
        if any(literal_value.endswith(ext) for ext in ['.js', '.jsx', '.ts', '.tsx', '.css', '.html', '.scss']):
            return None

        if any(keyword in literal_value for keyword in config['patterns']['suspicious_url_keywords']):
            return {
                "type": "Potential API Endpoint",
                "details": literal_value,
                "line": _get_line_number(node)
            }
    return None

def _check_high_entropy(node: dict, config: dict):
    if node.get('type') == 'Literal' and isinstance(node.get('value'), str):
        literal_value = node['value']
        
        # standard noise filter
        if any(literal_value.strip().startswith(prefix) for prefix in config['patterns']['ignore_prefixes']):
            return None
            
        if len(literal_value) >= config['patterns']['min_secret_length']:
            # first, check if it even looks like a secret (contains mix of chars)
            secret_regex = config['patterns']['secret_character_set_regex']
            if not re.match(secret_regex, literal_value):
                return None
                
            # then calculate entropy. high entropy usually means random data (like a key).
            entropy = shannon_entropy(literal_value)
            if entropy > config['patterns']['min_entropy_threshold']:
                return {
                    "type": "High Entropy String",
                    "details": f"Entropy: {round(entropy, 2)}, Value: '{literal_value[:100]}...'",
                    "line": _get_line_number(node)
                }
    return None

def _check_suspicious_headers(node: dict, config: dict):
    # looking for things like { "Authorization": "Bearer ..." }
    if node.get('type') == 'Property' and node.get('key', {}).get('name') == 'headers':
        if node.get('value', {}).get('type') == 'ObjectExpression':
            for prop in node['value'].get('properties', []):
                prop_key_node = prop.get('key', {})
                prop_name = prop_key_node.get('name') or prop_key_node.get('value')
                if isinstance(prop_name, str):
                    if any(keyword in prop_name.lower() for keyword in config['patterns']['suspicious_header_names']):
                        value_node = prop.get('value', {})
                        value_type = value_node.get('type', 'Unknown')
                        if value_type == 'Literal':
                            details = f"Header '{prop_name}' = Literal: '{str(value_node.get('value', ''))}'"
                        elif value_type == 'Identifier':
                            details = f"Header '{prop_name}' = Variable: {value_node.get('name', 'N/A')}"
                        else:
                            details = f"Header '{prop_name}' = Complex Value (Type: {value_type})"
                        return {
                            "type": "Suspicious HTTP Header",
                            "details": details,
                            "line": _get_line_number(prop_key_node)
                        }
    return None

def _check_suspicious_url_params(node: dict, config: dict):
    if node.get('type') == 'Literal' and isinstance(node.get('value'), str):
        literal_value = node['value']
        # we only care if it looks like a full url with parameters
        if 'http' in literal_value and '?' in literal_value:
            try:
                parsed_url = urlparse(literal_value)
                query_params = parse_qs(parsed_url.query)
                for param_name, param_values in query_params.items():
                    if param_name.lower() in config['patterns']['suspicious_url_params']:
                        return {
                            "type": "Suspicious URL Parameter",
                            "details": f"Param '{param_name}' in URL: {literal_value[:100]}...",
                            "line": _get_line_number(node)
                        }
            except Exception:
                return None
    return None

def _check_pii_in_node(node: dict, config: dict):
    if node.get('type') == 'Literal' and isinstance(node.get('value'), str):
        return _check_pii(
            node['value'], 
            _get_line_number(node), 
            "Code Literal", 
            config
        )
    return None

def _check_vendor_patterns(node: dict, config: dict):
    """
    checks for specific vendor formats (like aws keys starting with AKIA...).
    these are the highest confidence findings we have.
    """
    if node.get('type') == 'Literal' and isinstance(node.get('value'), str):
        literal_value = node['value']
        
        if any(literal_value.strip().startswith(prefix) for prefix in config['patterns'].get('ignore_prefixes', [])):
            return None

        for rule in config['patterns'].get('vendor_regexes', []):
            try:
                matches = re.findall(rule['pattern'], literal_value)
                for match in matches:
                    match_str = match if isinstance(match, str) else "-".join(match)
                    return {
                        "type": f"Vendor Secret: {rule['name']}",
                        "details": f"Found: '{match_str}'",
                        "line": _get_line_number(node)
                    }
            except re.error:
                continue
    return None

# --- main scan function ---

def _scan_ast_recursive(ast_node: dict, config: dict) -> Iterator[dict]:
    if not isinstance(ast_node, dict):
        return

    rules = [
        _check_vendor_patterns, 
        _check_suspicious_variable,
        _check_suspicious_property,
        _check_api_endpoint,
        _check_high_entropy,
        _check_suspicious_headers,
        _check_suspicious_url_params,
        _check_pii_in_node,
        _check_chromium_in_node
    ]

    for rule_func in rules:
        finding = rule_func(ast_node, config)
        if finding:
            yield finding
            # if we found a vendor secret or pii, stop processing this node.
            # we don't want to report "high entropy" for an aws key we already identified.
            if "Vendor Secret" in finding['type'] or "PII" in finding['type']:
                return

    for key, value in ast_node.items():
        if isinstance(value, dict):
            yield from _scan_ast_recursive(value, config)
        elif isinstance(value, list):
            for item in value:
                yield from _scan_ast_recursive(item, config)

def scan_ast_and_comments(parsed_data: dict, config: dict) -> Iterator[dict]:
    if not parsed_data:
        return

    ast = parsed_data.get('ast')
    comments = parsed_data.get('comments', [])

    if ast:
        yield from _scan_ast_recursive(ast, config)

    for comment in comments:
        if not isinstance(comment, dict): 
            continue
        
        comment_text = comment.get('value', '')
        line = _get_line_number(comment)
        
        # check config pii in comments
        finding = _check_pii(
            comment_text, 
            line, 
            "Comment", 
            config
        )
        if finding:
            yield finding
        
        # check chromium patterns in comments
        finding = _check_chromium_match(
            comment_text, 
            line, 
            "Comment"
        )
        if finding:
            yield finding