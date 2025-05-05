from dataclasses import dataclass

@dataclass
class AssignedVariable:
    name: str
    value: str
    line: int
    column: int

@dataclass
class UsedVariable:
    name: str
    line: int
    column: int