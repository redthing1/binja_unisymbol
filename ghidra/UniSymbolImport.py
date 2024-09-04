# UniSymbolImport.py
#@category Symbols
#@keybinding 
#@menupath Tools.UniSymbol.Import Symbols (CSV)
#@toolbar 
#@description Imports symbols from the unified UniSymbol-CSV format.

import csv
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import Function
from ghidra.program.model.address import Address
from ghidra.program.model.symbol import SymbolTable
from ghidra.program.model.data import DataUtilities
from ghidra.util.exception import InvalidInputException
from ghidra.util.task import TaskMonitor

# Symbol type mapping
SYMBOL_TYPES = {
    "UNKNOWN": "unknown",
    "DATA_LABEL": "data_label",
    "INSTRUCTION_LABEL": "instruction_label",
    "FUNCTION": "function",
    "THUNK_FUNCTION": "thunk_function"
}

# Symbol reason mapping
SYMBOL_REASONS = {
    "AUTO_ANALYSIS": SourceType.ANALYSIS,
    "USER_DEFINED": SourceType.USER_DEFINED
}

def create_summary(name, addr, sym_type, module, source, reason):
    """
    Create a summary string for the symbol.
    """
    summary = "{}: {} @ ".format(source, name)
    if module:
        summary += "{}+".format(module)
    summary += "{:08x} ({} {})".format(addr, reason, sym_type)
    return summary

def import_unisymbols(csv_path, monitor):
    """
    Import symbols from the CSV file.
    """
    program = getCurrentProgram()
    memory = program.getMemory()
    symbol_table = program.getSymbolTable()
    listing = program.getListing()
    
    imported_count = 0
    skipped_count = 0
    
    with open(csv_path, 'rb') as csvfile:
        reader = csv.DictReader(csvfile)
        total_symbols = sum(1 for row in reader)
        csvfile.seek(0)
        reader.next()  # skip header
        
        for i, row in enumerate(reader):
            if monitor.isCancelled():
                break
            
            monitor.setProgress(i * 100 / total_symbols)
            monitor.setMessage("Importing symbol {} of {}".format(i+1, total_symbols))
            
            # Extract data from CSV row
            name = row['name']
            addr = int(row['addr'], 16)
            sym_type = row['type']
            module = row['module'] if row['module'] else None
            source = row['source']
            reason = row['reason']
            
            address = toAddr(addr)
            if not memory.contains(address):
                print "Skipping symbol {} at {}: address not in memory".format(name, address)
                skipped_count += 1
                continue
            
            # Determine the correct source type based on the reason
            source_type = SYMBOL_REASONS.get(reason, SourceType.IMPORTED)
            
            try:
                # Create the appropriate symbol type
                if SYMBOL_TYPES[sym_type] in ['function', 'thunk_function']:
                    func = listing.getFunctionAt(address)
                    if not func:
                        func = createFunction(address, name)
                    if func:
                        func.setName(name, source_type)
                        if SYMBOL_TYPES[sym_type] == 'thunk_function':
                            func.setThunk(True)
                elif SYMBOL_TYPES[sym_type] == 'data_label':
                    symbol_table.createLabel(address, name, source_type)
                    DataUtilities.createData(program, address, None, 1, False, DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA)
                elif SYMBOL_TYPES[sym_type] == 'instruction_label':
                    symbol_table.createLabel(address, name, source_type)
                else:
                    symbol_table.createLabel(address, name, source_type)
                
                # Create and set the summary as a plate comment
                summary = create_summary(name, addr, sym_type, module, source, reason)
                setPlateComment(address, summary)
                
                print "Imported symbol: {} at {}".format(name, address)
                imported_count += 1
            except InvalidInputException as e:
                print "Error importing symbol {} at {}: {}".format(name, address, str(e))
                skipped_count += 1
    
    print "Finished importing symbols"
    print "Imported: {}, Skipped: {}".format(imported_count, skipped_count)
    return imported_count, skipped_count

def run():
    """
    Main function to run the script.
    """
    csv_path = askFile("Select UniSymbol CSV file", "Import").getPath()
    monitor = TaskMonitor.DUMMY
    imported, skipped = import_unisymbols(csv_path, monitor)
    
    popup_message = "Import completed!\n\nImported: {}\nSkipped: {}".format(imported, skipped)
    popup(popup_message)

if __name__ == '__main__':
    run()