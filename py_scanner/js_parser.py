import esprima
import re

def parse_js_to_ast(js_code: str) -> dict | None:
    if not js_code: return None

    # --- STRATEGY 1: Try parsing standard JS ---
    try:
        parsed = esprima.parseModule(js_code, options={'loc': True, 'comment': True})
        return _package_ast(parsed)
    except Exception:
        pass # Fall through to Strategy 2

    # --- STRATEGY 2: Naive JSX Stripping ---
    # Remove anything that looks like an XML tag <...>.
    # This is destructive but preserves the JS logic around it.
    # Regex explanation: Match <...> OR </...> and replace with empty string.
    # Note: This is imperfect but often allows Esprima to parse the remaining JS.
    try:
        clean_code = re.sub(r'<[^>]+>', '', js_code)
        parsed = esprima.parseModule(clean_code, options={'loc': True, 'comment': True})
        return _package_ast(parsed)
    except Exception:
        return None

def _package_ast(parsed):
    """Helper to package the result consistently."""
    ast_dict = parsed.toDict()
    raw_comments = parsed.comments if hasattr(parsed, 'comments') else []
    clean_comments = []
    for c in raw_comments:
        if hasattr(c, 'toDict'): clean_comments.append(c.toDict())
        elif isinstance(c, dict): clean_comments.append(c)
    return {"ast": ast_dict, "comments": clean_comments}