from bashguard.core.vulnerability import Vulnerability

class Fixer:
    """
    Fixer class that fixes the code according to found vulnerabilities.
    """
    
    def __init__(self, script_path):
        """
        Initialize the fixer.
        
        Args:
            script_path: path of the script.
        """
        self.script_path = script_path
        with open(script_path, "r") as f:
            self.content = f.readlines()

    
    def fix(self, vulnerabilities: list[Vulnerability]):
        """
        Fix the code according to the vulnerabilities.
        
        Args:
            vulnerabilitiesvu: found vulnerabilities.
        """

        for vuln in vulnerabilities:
            line_number = vuln.line_number - 1
            column = vuln.column - 1
            line_content = vuln.line_content

            # print("line_content: \n", line_content.encode())

            original_line_content = self.content[line_number]
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
            import re
            match = re.match(r'[\$a-zA-Z0-9_*#@]*', suf)
            # print(suf)
            assert match

            var = match.group(0)

            # assemble back with quotes added
            fixed_line = pre + "\"" + var + "\"" + suf[match.end():] + "\n"
            
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
                


            self.content[line_number] = fixed_line


        
        # fixed_code = "\n".join(self.content)
        fixed_code = ""
        for line in self.content:
            fixed_code += line
        with open(self.script_path, "w") as f:
            f.write(fixed_code)

