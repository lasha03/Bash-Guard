import os
from bashguard.core import TSParser
from bashguard.core.types import ValueParameterExpansion, ValueUserInput, ValuePlainVariable
def test_get_variables():
    
    content = ""
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_parser.sh')
    with open(test_file_path, 'r') as f:
        content = f.read()

    parser = TSParser(bytes(content, 'utf-8'))
    assigned_variables = parser.get_variables()

    assert len(assigned_variables) == 5
    
    assert assigned_variables[0].name == 'PATH'
    assert assigned_variables[0].value.content == '/usr/bin'
    assert assigned_variables[0].value.sensitive_parts == []

    assert assigned_variables[1].name == 'a'

    assert assigned_variables[1].name == "a"
    assert len(assigned_variables[1].value.sensitive_parts) == 1
    assert isinstance(assigned_variables[1].value.sensitive_parts[0], ValuePlainVariable)

    assert assigned_variables[2].name == 'b'
    assert len(assigned_variables[2].value.sensitive_parts) == 1
    assert isinstance(assigned_variables[2].value.sensitive_parts[0], ValueParameterExpansion)
    
    assert assigned_variables[3].name == 'c'
    assert len(assigned_variables[3].value.sensitive_parts) == 0
    
    assert assigned_variables[4].name == 'd'
    assert len(assigned_variables[4].value.sensitive_parts) == 1

    # Check tainted variables
    tainted_variables = parser.get_tainted_variables()
    assert len(tainted_variables) == 2 # read not implemented yet
    assert 'a' in tainted_variables
    assert 'b' in tainted_variables
