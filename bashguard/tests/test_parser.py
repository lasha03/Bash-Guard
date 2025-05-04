import os
from bashguard.core import Parser

def test_get_variables():
    
    content = ""
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_parser.sh')
    with open(test_file_path, 'r') as f:
        content = f.read()

    p = Parser(content)
    p.parse()
    res = p.get_variables()[0]
    assert res.kind == 'assignment'
    assert res.word == 'PATH=/usr/bin'