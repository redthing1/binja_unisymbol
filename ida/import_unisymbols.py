import csv
import idaapi
import idc
import ida_funcs
import ida_name
import ida_bytes
import ida_kernwin
import ida_auto

# Symbol type mapping
SYMBOL_TYPES = {
    "UNKNOWN": 0,
    "DATA_LABEL": 1,
    "INSTRUCTION_LABEL": 2,
    "FUNCTION": 3,
    "THUNK_FUNCTION": 4
}

# Symbol reason mapping
SYMBOL_REASONS = {
    "AUTO_ANALYSIS": 0,
    "USER_DEFINED": 1
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

def set_name_based_on_reason(addr, name, reason):
    """
    Set name based on whether it's user-defined or auto-generated.
    """
    if SYMBOL_REASONS[reason] == SYMBOL_REASONS["USER_DEFINED"]:
        # For user-defined symbols, use set_name which creates a user-defined name
        return ida_name.set_name(addr, name, ida_name.SN_CHECK)
    else:
        # For auto-generated symbols, use force_name which creates an auto-generated name
        return ida_name.force_name(addr, name)

def import_unisymbols(csv_path):
    """
    Import symbols from the CSV file.
    """
    imported_count = 0
    skipped_count = 0

    with open(csv_path, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        total_symbols = sum(1 for _ in reader)
        csvfile.seek(0)
        next(reader)  # skip header

        for i, row in enumerate(reader):
            if i % 100 == 0:
                idaapi.replace_wait_box("Importing symbol {} of {}".format(i+1, total_symbols))

            # Extract data from CSV row
            name = row['name']
            addr = int(row['addr'], 16)
            sym_type = row['type']
            module = row['module'] if row['module'] else None
            source = row['source']
            reason = row['reason']

            if not idaapi.is_loaded(addr):
                print("Skipping symbol {} at {:#x}: address not loaded".format(name, addr))
                skipped_count += 1
                continue

            try:
                # Create the appropriate symbol type
                if SYMBOL_TYPES[sym_type] in [SYMBOL_TYPES["FUNCTION"], SYMBOL_TYPES["THUNK_FUNCTION"]]:
                    if not ida_funcs.get_func(addr):
                        ida_funcs.add_func(addr)
                    set_name_based_on_reason(addr, name, reason)
                    if SYMBOL_TYPES[sym_type] == SYMBOL_TYPES["THUNK_FUNCTION"]:
                        func = ida_funcs.get_func(addr)
                        if func:
                            func.flags |= ida_funcs.FUNC_THUNK
                            ida_funcs.update_func(func)
                elif SYMBOL_TYPES[sym_type] in [SYMBOL_TYPES["DATA_LABEL"], SYMBOL_TYPES["INSTRUCTION_LABEL"], SYMBOL_TYPES["UNKNOWN"]]:
                    set_name_based_on_reason(addr, name, reason)

                # Create and set the summary as a comment
                summary = create_summary(name, addr, sym_type, module, source, reason)
                ida_bytes.set_cmt(addr, summary, 1)  # 1 means repeatable comment

                print("Imported symbol: {} at {:#x} ({})".format(name, addr, reason))
                imported_count += 1
            except Exception as e:
                print("Error importing symbol {} at {:#x}: {}".format(name, addr, str(e)))
                skipped_count += 1

    print("Finished importing symbols")
    print("Imported: {}, Skipped: {}".format(imported_count, skipped_count))
    return imported_count, skipped_count

def run():
    """
    Main function to run the script.
    """
    csv_path = ida_kernwin.ask_file(0, "*.csv", "Select UniSymbol CSV file")
    if not csv_path:
        print("No file selected. Exiting.")
        return

    idaapi.show_wait_box("Importing UniSymbols...")
    try:
        ida_auto.set_ida_state(ida_auto.IDA_STATE_SUSPENDED)  # Suspend auto-analysis
        imported, skipped = import_unisymbols(csv_path)
    finally:
        ida_auto.set_ida_state(ida_auto.IDA_STATE_AUTO)  # Resume auto-analysis
        idaapi.hide_wait_box()

    ida_kernwin.info("Import completed!\n\nImported: {}\nSkipped: {}".format(imported, skipped))

if __name__ == '__main__':
    run()