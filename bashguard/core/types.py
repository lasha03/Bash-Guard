from dataclasses import dataclass
from typing import List

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

@dataclass
class Command:
    name: str
    arguments: List[str]
    line: int
    column: int