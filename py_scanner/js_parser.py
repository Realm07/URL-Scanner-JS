import esprima
import re

def parse_js_to_ast(js_code: str) -> dict | None:
    if not js_code: 
        return None

    # --- strategy 1: try parsing standard js ---
    # this is the happy path. if the code is valid es5/es6, esprima handles it.
    try:
        parsed = esprima.parseModule(
            js_code, 
            options={
                'loc': True, 
                'comment': True
            }
        )
        return _package_ast(parsed)
    except Exception:
        pass # fall through to strategy 2

    # --- strategy 2: naive jsx stripping ---
    # okay, this is a bit of a hack. esprima chokes on jsx (react syntax),
    # so we just brutally rip out anything that looks like an xml tag.
    # it's destructive, but it preserves the underlying logic which is what we care about.
    # we're basically betting that the security flaw isn't inside the html tag itself.
    try:
        clean_code = re.sub(r'<[^>]+>', '', js_code)
        parsed = esprima.parseModule(
            clean_code, 
            options={
                'loc': True, 
                'comment': True
            }
        )
        return _package_ast(parsed)
    except Exception:
        return None

def _package_ast(parsed):
    """
    just a helper to make sure our output format is consistent
    regardless of which parser strategy succeeded.
    """
    ast_dict = parsed.toDict()
    
    # handle cases where comments might be missing or in a weird format
    raw_comments = parsed.comments if hasattr(parsed, 'comments') else []
    
    clean_comments = []
    for c in raw_comments:
        if hasattr(c, 'toDict'): 
            clean_comments.append(c.toDict())
        elif isinstance(c, dict): 
            clean_comments.append(c)
            
    return {
        "ast": ast_dict, 
        "comments": clean_comments
    }