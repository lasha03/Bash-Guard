from dataclasses import dataclass
from typing import List, Optional, Union, TypeAlias

@dataclass
class ValueParameterExpansion:
    """
    Represents a parameter expansion that is inside a value.

    For example:
        - ${VAR}, where `prefix = ""`, `variable = "VAR"`
        - ${!VAR}, where `prefix = "!"`, `variable = "VAR"`
        - ${ARRAY[INDEX]}, where `prefix = ""`, `variable = "ARRAY[INDEX]"`
    """
    # whole value as string
    content: str

    # used variable name, like '1', '@', 'VAR', etc.
    variable: str

    # ${!VAR} -> '!', ${#VAR} -> '#'
    # this is called 'indirect variable referencing'
    # '!' may result in exploit
    prefix: str

    # column frame of the variable name
    column_frame: Optional[tuple[int, int]] = None # start_point and end_point

@dataclass
class ValuePlainVariable:
    """
    Represents a plain variable.

    For example:
        - $VAR
        - $0, $1, etc.
        - $_, $*, $@, $#, etc.
    """

    # used variable name, like '1', '@', 'VAR', etc.
    variable: str

    # column frame of the variable name
    column_frame: Optional[tuple[int, int]] = None # start_point and end_point

@dataclass
class ValueUserInput:
    """
    Placeholder for user input.
    """
    pass

@dataclass
class ValueCommandSubtitution:
    """
    Represents value as command when having command subtitution
    
    For example $foo=$($bar)
    """
    command: "Command"


SensitiveValueUnionType: TypeAlias = Union[ValueParameterExpansion, ValuePlainVariable, ValueUserInput, ValueCommandSubtitution]

@dataclass
class Value:
    """
    Represents a value that is inside a value node.
    """

    # whole value as string
    content: str

    # list of sensitive parts
    sensitive_parts: list[SensitiveValueUnionType]

@dataclass
class AssignedVariable:
    name: str
    value: Value
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