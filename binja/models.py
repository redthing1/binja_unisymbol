import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Tuple, Optional, Any


@dataclass
class UniSymbol:
    class SymbolType(Enum):
        UNKNOWN = 0
        DATA_LABEL = 1
        INSTRUCTION_LABEL = 2
        FUNCTION = 3
        THUNK_FUNCTION = 4

    class SymbolReason(Enum):
        AUTO_ANALYSIS = 0
        USER_DEFINED = 1

    # the name of the symbol
    name: str
    # the address of the symbol within the module
    addr: int
    # the type of the symbol
    type: SymbolType
    # an empty module means the symbol is from the main binary
    module: Optional[str] = None
    # where the symbol is imported from
    source: Optional[str] = None
    # the reason the symbol was created
    reason: SymbolReason = SymbolReason.AUTO_ANALYSIS
    # whether the symbol should override existing symbols
    priority: int = 1

    def is_external(self) -> bool:
        return self.module is not None

    def summary(self) -> str:
        if self.is_external():
            return f"{self.source}: {self.name} @ {self.module}+{self.addr:08x} ({self.reason.name} {self.type.name})"

        return f"{self.source}: {self.name} @ {self.addr:08x} ({self.reason.name} {self.type.name})"

    def __repr__(self) -> str:
        return f"UniSymbol({self.name} @ {self.addr:08x}, type={self.type.name}, module={self.module}, source={self.source}, reason={self.reason.name})"


@dataclass
class UniXref:
    class ReferenceType(Enum):
        UNKNOWN = 0
        CALL = 1
        JUMP = 2
        DATA_READ = 3
        DATA_WRITE = 4
        IMPORT = 5
        EXPORT = 6

    # Source of the reference
    from_addr: int
    # Target of the reference
    to_addr: int
    # Type of reference
    ref_type: ReferenceType
    # Module containing the source address (None for main binary)
    from_module: Optional[str] = None
    # Module containing the target address (None for main binary)
    to_module: Optional[str] = None
    # Symbol at the source address (if any)
    from_symbol: Optional[str] = None
    # Symbol at the target address (if any)
    to_symbol: Optional[str] = None
    # Disassembler-specific metadata (optional)
    metadata: Optional[dict] = None

    def is_external(self) -> bool:
        return self.from_module != self.to_module

    def summary(self) -> str:
        from_loc = f"{self.from_module}:" if self.from_module else ""
        from_loc += f"{self.from_addr:08x}"
        from_loc += f" ({self.from_symbol})" if self.from_symbol else ""

        to_loc = f"{self.to_module}:" if self.to_module else ""
        to_loc += f"{self.to_addr:08x}"
        to_loc += f" ({self.to_symbol})" if self.to_symbol else ""

        return f"{from_loc} -> {to_loc} [{self.ref_type.name}]"

    def __repr__(self) -> str:
        return f"UniXref(from={self.from_addr:08x}, to={self.to_addr:08x}, type={self.ref_type.name})"


@dataclass
class GhidraCSVSymbol:
    # "Name","Location","Type","Namespace","Source","Reference Count","Offcut Ref Count"
    name: str
    loc: str
    # Types: Data Label,External Data,External Function,Function,Instruction Label,Thunk Function,Unknown
    # https://github.com/NationalSecurityAgency/ghidra/blob/184180d54dbdf3db3c030ead3772f6f8f46f9d72/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/symbol/SymbolUtilities.java#L899C2-L949C3
    type: str
    namespace: str
    source: str
    ref_count: int

    def is_within_current_module(self) -> bool:
        return bool(re.match(r"(0x)?[0-9a-fA-F]+", self.loc))

    def is_external(self) -> bool:
        return bool(re.match(r"External\[(.+)\]", self.loc))

    def is_function(self) -> bool:
        return self.type == "Function"

    def is_instruction_label(self) -> bool:
        return self.type == "Instruction Label"

    def is_data_label(self) -> bool:
        return self.type == "Data Label"

    def is_unknown(self) -> bool:
        return self.type == "Unknown"

    def is_thunk_function(self) -> bool:
        return self.type == "Thunk Function"

    def is_user_defined(self) -> bool:
        return self.source == "User Defined"

    def __repr__(self) -> str:
        return f"GhidraSymbol({self.name} @ {self.loc}, type={self.type}, ns={self.namespace}, source={self.source}, ref_count={self.ref_count})"
