from dataclasses import dataclass
from typing import List, Optional

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

@dataclass
class Subscript:
    """Represents an array subscript."""
    array_name: str
    index_expression: str
    line: int
    column: int