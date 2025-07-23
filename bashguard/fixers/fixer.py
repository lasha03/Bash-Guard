from bashguard.core.vulnerability import Vulnerability
from collections import defaultdict
from bashguard.fixers.variable_expansion_fixer import VariableExpansionFixer
from bashguard.core.vulnerability import Description
from bashguard.fixers.command_substitution_fixer import CommandSubstitutionFixer

class Fixer:
    """
    Fixer class that fixes the code according to found vulnerabilities.
    """
    
    def __init__(self, script_path, output_path=None):
        """
        Initialize the fixer.
        
        Args:
            script_path: path of the script.
            output_path: path of the output file.
        """
        self.script_path = script_path

        if output_path:
            self.output_path = output_path
        else:
            self.output_path = self.script_path

        with open(script_path, "r") as f:
            self.content = f.readlines()

        self.init_fixers()

    def init_fixers(self):
        self.fixers = {
            Description.VARIABLE_EXPANSION.value: VariableExpansionFixer(),
            Description.UNQUOTED_COMMAND_SUBSTITUTION.value: CommandSubstitutionFixer()
        } # type: dict[Description, BaseFixer]
    
    
    def fix(self, vulnerabilities: list[Vulnerability]):
        """
        Fix the code according to the vulnerabilities.
        
        Args:
            vulnerabilitiesvu: found vulnerabilities.
        """

        vulns_by_line = defaultdict(list)
        for vuln in vulnerabilities:
            line_number = vuln.line_number - 1
            vulns_by_line[line_number].append(vuln)
            # column = vuln.column - 1
            # line_content = vuln.line_content

            # print("line_content: \n", line_content.encode())

        for line_number, vulns in vulns_by_line.items():
            # Sort vulnerabilities by column ascending
            vulns_sorted = sorted(vulns, key=lambda v: v.column)
            
            base_column = 0
            line_content = self.content[line_number]
            original_line_content = self.content[line_number]
            
            for vuln in vulns_sorted:
                try:
                    fixer = self.fixers[vuln.description]
                except KeyError:
                    continue
                
                fixed_line, num_chars_added = fixer.fix(vuln, line_content, original_line_content, base_column)
                
                line_content = fixed_line
                original_line_content = fixed_line

                base_column += num_chars_added

            self.content[line_number] = line_content


        fixed_code = "".join(self.content)
        
        with open(self.output_path, "w") as f:
            f.write(fixed_code)

