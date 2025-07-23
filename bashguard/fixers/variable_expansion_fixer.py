import re

from bashguard.core.base_fixer import BaseFixer
from bashguard.core import Vulnerability

class VariableExpansionFixer(BaseFixer):
    def __init__(self):
        self.num_chars_to_add = 2

    def fix(self, vulnerability: Vulnerability, line_content: str, original_line_content: str, base_column: int) -> tuple[str, int]:
        column = base_column + vulnerability.column - 1

        # expand tabs to spaces
        line_content = line_content

        # print("original_line_content: \n", original_line_content)
        # print(column)

        while column > 0 and line_content[column] != '$':
            column -= 1

        assert line_content[column] == '$'

        pre = line_content[:column]
        suf = line_content[column:]

        # extract var name
        match = re.match(r'[\$a-zA-Z0-9_*#@]*', suf)
        # print(suf)
        assert match

        var = match.group(0)

        # assemble back with quotes added
        fixed_line = pre + "\"" + var + "\"" + suf[match.end():]
        
        # add tabs back
        i = 0
        for c in original_line_content:
            # skip quotes
            if i == column:
                i += 1
            if i == column + len(var) + 1:
                i += 1
            
            # shrink spaces back to tab
            if c == '\t':
                assert all(c == ' ' for c in fixed_line[i:i+8].strip())
                fixed_line = fixed_line[:i] + "\t" + fixed_line[i+8:]

        return fixed_line, self.num_chars_to_add
