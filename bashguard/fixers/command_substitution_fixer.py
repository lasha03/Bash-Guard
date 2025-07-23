import re
from bashguard.core.base_fixer import BaseFixer
from bashguard.core import Vulnerability

class CommandSubstitutionFixer(BaseFixer):
    def __init__(self):
        self.num_chars_to_add = 2  # for the quotes

    def fix(self, vulnerability: Vulnerability, line_content: str, original_line_content: str, base_column: int) -> tuple[str, int]:
        column = base_column + vulnerability.column - 1
        
        start = column
        
        # find the matching closing parenthesis for this $(
        open_parens = 0
        end = None
        for i in range(start+1, len(line_content)):
            if line_content[i] == '(':
                open_parens += 1
            elif line_content[i] == ')':
                open_parens -= 1
                if open_parens == 0:
                    end = i
                    break
        
        if end is None:
            return line_content, 0  # unmatched parens

        end += 1
        
        inner = line_content[start:end]
        
        # Insert quotes around the inner command
        fixed_line = (
            line_content[:start] + '"' + inner + '"' + line_content[end:]
        )

        return fixed_line, self.num_chars_to_add
