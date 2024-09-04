# UniXrefExport.py
# @category Xrefs
# @keybinding
# @menupath Tools.UniSymbol.Export Xrefs (CSV)
# @toolbar
# @description Exports cross-references to the unified UniXref-CSV format.

import csv
from ghidra.program.model.symbol import SymbolType, RefType
from ghidra.program.model.listing import CodeUnit
from ghidra.program.util import ProgramMemoryUtil

def get_unixref_type(ref_type):
    if ref_type.isCall():
        return "CALL"
    elif ref_type.isJump():
        return "JUMP"
    elif ref_type.isRead():
        return "DATA_READ"
    elif ref_type.isWrite():
        return "DATA_WRITE"
    elif ref_type == RefType.EXTERNAL_REF:
        return "IMPORT"
    else:
        return "UNKNOWN"

def get_symbol_name(address):
    symbol = getSymbolAt(address)
    return symbol.getName() if symbol else None

def get_module_name(address):
    space_name = address.getAddressSpace().getName()
    return space_name if space_name != "ram" else None

def format_address(addr):
    return "0x{:x}".format(addr.getOffset())

def export_unixrefs_to_csv(output_path):
    program = getCurrentProgram()
    memory = program.getMemory()
    listing = program.getListing()
    
    with open(output_path, "wb") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["from_addr", "to_addr", "ref_type", "from_module", "to_module", "from_symbol", "to_symbol"])
        
        # Iterate through all memory blocks
        for block in memory.getBlocks():
            if block.isInitialized():
                start = block.getStart()
                end = block.getEnd()
                
                # Use the listing to iterate through all defined code units in the block
                address = start
                while address <= end:
                    cu = listing.getCodeUnitAt(address)
                    if cu is not None:
                        refs = cu.getReferencesFrom()
                        for ref in refs:
                            from_addr = ref.getFromAddress()
                            to_addr = ref.getToAddress()
                            
                            unixref_type = get_unixref_type(ref.getReferenceType())
                            from_module = get_module_name(from_addr)
                            to_module = get_module_name(to_addr)
                            from_symbol = get_symbol_name(from_addr)
                            to_symbol = get_symbol_name(to_addr)
                            
                            writer.writerow([
                                format_address(from_addr),
                                format_address(to_addr),
                                unixref_type,
                                from_module if from_module else "",
                                to_module if to_module else "",
                                from_symbol if from_symbol else "",
                                to_symbol if to_symbol else ""
                            ])
                        
                        address = address.add(cu.getLength())
                    else:
                        address = address.next()

    print("Exported UniXrefs to: " + output_path)

def run():
    output_file = askFile("Select output UniXref CSV file", "Save").getPath()
    export_unixrefs_to_csv(output_file)

if __name__ == "__main__":
    run()