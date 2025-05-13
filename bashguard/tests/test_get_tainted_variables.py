import os
from bashguard.core import TSParser

def test_get_tainted_variables():
    
    content = ""
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_get_tainted_variables.sh')
    with open(test_file_path, 'r') as f:
        content = f.read()

    parser = TSParser(bytes(content, 'utf-8'))
    res = parser.get_tainted_variables()
    
    assert len(res) == 1
    assert "gio" in res

test_get_tainted_variables()