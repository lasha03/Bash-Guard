import os
from bashguard.core import TSParser

def test_get_tainted_variables():
    
    content = ""
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_get_tainted_variables.sh')
    with open(test_file_path, 'r') as f:
        content = f.read()

    parser = TSParser(bytes(content, 'utf-8'))
    res = parser.get_tainted_variables()
    
    print(res)
    assert len(res) == 5
    assert "gio" in res and "mama" in res and "myFunction.deda" in res and "fxala" in res and "lasha" in res

test_get_tainted_variables()