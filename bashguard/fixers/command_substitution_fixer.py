from bashguard.core import BaseFixer, Vulnerability

class CommandSubstitutionFixer(BaseFixer):
    def fix(self, vulnerability: Vulnerability, line_content: str, original_line_content: str, base_column: int) -> tuple[str, int]:
        column = base_column + vulnerability.column - 1
        
        start = column
        # print(line_content[start], line_content)
        if line_content[start] == '`':
            return self.fix_backticks(vulnerability, line_content, start)
        elif line_content[start] == '$':
            return self.fix_parentheses(vulnerability, line_content, start)
        else:
            return line_content, 0
        
        

    def fix_backticks(self, vulnerability: Vulnerability, line_content: str, start: int) -> tuple[str, int]:
        end = line_content.find('`', start+1)
        if end == -1:
            return line_content, 0
        inner = line_content[start+1:end]
        return line_content[:start] + '"$(' + inner + ')"' + line_content[end+1:], 3 # delete two backticks and add "$()"

    def fix_parentheses(self, vulnerability: Vulnerability, line_content: str, start: int) -> tuple[str, int]:
        # find the matching closing parenthesis for this $(
        open_parens = 0
        end = None
        for i in range(start, len(line_content)):
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


        return line_content[:start] + '"' + inner + '"' + line_content[end:], 2