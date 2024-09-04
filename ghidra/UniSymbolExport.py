# UniSymbolExport.py
# @category Symbols
# @keybinding
# @menupath Tools.UniSymbol.Export Symbols (CSV)
# @toolbar
# @description Exports symbols to the unified UniSymbol-CSV format.

import csv
from ghidra.program.model.symbol import SymbolType, SourceType
from ghidra.program.model.listing import Function, Instruction, Data


def get_unisymbol_type(symbol):
    if symbol.isExternal():
        if symbol.getSymbolType() == SymbolType.FUNCTION:
            return "FUNCTION"  # External Function
        else:
            return "DATA_LABEL"  # External Data

    if symbol.getSymbolType() == SymbolType.FUNCTION:
        func = symbol.getObject()
        if func and isinstance(func, Function):
            if func.isThunk():
                return "THUNK_FUNCTION"
            return "FUNCTION"

    if symbol.getSymbolType() == SymbolType.LABEL:
        if not symbol.isPrimary():
            program = symbol.getProgram()
            primary = program.getSymbolTable().getPrimarySymbol(symbol.getAddress())
            if primary and primary.getSymbolType() == SymbolType.FUNCTION:
                return "FUNCTION"

        obj = symbol.getObject()
        if isinstance(obj, Instruction):
            return "INSTRUCTION_LABEL"
        elif isinstance(obj, Data):
            return "DATA_LABEL"

    # if we still don't know what it is but it's user defined, treat it as a data label
    if symbol.getSource() == SourceType.USER_DEFINED:
        return "DATA_LABEL"

    # Default case
    return "UNKNOWN"


def get_symbol_reason(symbol):
    return (
        "USER_DEFINED"
        if symbol.getSource() == SourceType.USER_DEFINED
        else "AUTO_ANALYSIS"
    )


def get_symbol_module(symbol):
    address = symbol.getAddress()
    if address is None:
        return None

    space_name = address.getAddressSpace().getName()
    return (
        space_name if space_name != "ram" else None
    )  # Adjust "ram" based on your main program space


def export_unisymbols_to_csv(output_path):
    program = getCurrentProgram()
    symbol_table = program.getSymbolTable()
    symbol_iter = symbol_table.getAllSymbols(True)

    with open(output_path, "wb") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["name", "addr", "type", "module", "source", "reason"])

        for symbol in symbol_iter:
            # Skip parameters and local variables
            if symbol.getSymbolType() in [SymbolType.PARAMETER, SymbolType.LOCAL_VAR]:
                continue

            name = symbol.getName()
            addr = symbol.getAddress().getOffset()
            sym_type = get_unisymbol_type(symbol)
            module = get_symbol_module(symbol)
            source = "ghidra"
            reason = get_symbol_reason(symbol)

            writer.writerow(
                [name, hex(addr), sym_type, module if module else "", source, reason]
            )

    print("Exported UniSymbols to: " + output_path)


def run():
    output_file = askFile("Select output UniSymbol CSV file", "Save").getPath()
    export_unisymbols_to_csv(output_file)


if __name__ == "__main__":
    run()
