import os
from bashguard.core import TSParser
from pathlib import Path

def test_subscript_detection():
    """Test that the TSParser correctly detects array subscripts."""

    test_file_path = os.path.join(os.path.dirname(__file__), 'test_subscript_detection.sh')
    with open(test_file_path, 'r') as f:
        content = f.read()
    
    parser = TSParser(bytes(content, 'utf-8'))
    subscripts = parser.get_subscripts()
    
    assert len(subscripts) == 4
    
    array_names = [s.array_name for s in subscripts]
    index_expressions = [s.index_expression for s in subscripts]

    assert "array1" in array_names
    assert "array2" in array_names
    assert "array3" in array_names
    assert "my_array" in array_names

    assert "$(cat /flag)" in index_expressions
    assert "$user_input" in index_expressions
    assert "$i" in index_expressions
    assert "@" in index_expressions
    
    