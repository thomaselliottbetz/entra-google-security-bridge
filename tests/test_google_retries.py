import ast
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import collaboration_security_google as g


def test_every_google_execute_call_passes_num_retries():
    """Guards against a new Google API call being added without retry on 429/5xx."""
    tree = ast.parse(open(g.__file__).read())
    bare = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "execute"
        and not any(kw.arg == "num_retries" for kw in node.keywords)
    ]
    assert bare == [], f"execute() without num_retries at lines {bare}"
