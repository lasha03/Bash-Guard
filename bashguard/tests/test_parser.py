import os
from bashguard.core import TSParser

def test_get_variables():
    
    content = ""
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_parser.sh')
    with open(test_file_path, 'r') as f:
        content = f.read()

    parser = TSParser(bytes(content, 'utf-8'))
    res = parser.get_variables()
    
    assert len(res) == 1
    assert res[0].name == 'PATH'
    assert res[0].value == '/usr/bin'