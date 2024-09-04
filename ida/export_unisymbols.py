import csv
import idaapi
import idautils
import ida_bytes
import ida_funcs
import ida_name
import ida_segment
import ida_xref
import ida_kernwin
import ida_nalt
import ida_idd


# UniSymbol Types
class UniSymbolType:
    UNKNOWN = "UNKNOWN"
    DATA_LABEL = "DATA_LABEL"
    INSTRUCTION_LABEL = "INSTRUCTION_LABEL"
    FUNCTION = "FUNCTION"
    THUNK_FUNCTION = "THUNK_FUNCTION"


# UniSymbol Reasons
class UniSymbolReason:
    AUTO_ANALYSIS = "AUTO_ANALYSIS"
    USER_DEFINED = "USER_DEFINED"


def get_symbol_type(ea):
    flags = ida_bytes.get_flags(ea)
    if ida_bytes.is_code(flags):
        func = ida_funcs.get_func(ea)
        if func:
            if func.flags & ida_funcs.FUNC_THUNK:
                return UniSymbolType.THUNK_FUNCTION
            return UniSymbolType.FUNCTION
        return UniSymbolType.INSTRUCTION_LABEL
    elif ida_bytes.is_data(flags):
        return UniSymbolType.DATA_LABEL
    return UniSymbolType.UNKNOWN


def get_symbol_reason(ea):
    flags = ida_bytes.get_flags(ea)
    if ida_bytes.has_user_name(flags):
        # Check if the name is not auto-generated
        name = ida_name.get_ea_name(ea)
        if (
            not name.startswith("sub_")
            and not name.startswith("loc_")
            and not name.startswith("unk_")
        ):
            return UniSymbolReason.USER_DEFINED
    return UniSymbolReason.AUTO_ANALYSIS


def get_symbol_module(ea):
    # Create a module info object
    modinfo = ida_idd.modinfo_t()

    # Try to get module info
    if ida_dbg.get_module_info(ea, modinfo):
        # If module info is available, return the module name
        # We'll extract just the filename from the full path
        return modinfo.name.split("\\")[-1].split("/")[-1]

    # If we couldn't determine a module, it's likely in the main binary
    return None


def get_reference_count(ea):
    return len(list(idautils.XrefsTo(ea)))


def export_unisymbols(output_path):
    with open(output_path, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(
            ["name", "addr", "type", "module", "source", "reason", "ref_count"]
        )

        # Set to keep track of processed addresses
        processed_addresses = set()

        # First, process all functions (including sub_...)
        for ea in idautils.Functions():
            name = ida_name.get_ea_name(ea)
            sym_type = get_symbol_type(ea)
            module = get_symbol_module(ea)
            reason = get_symbol_reason(ea)
            ref_count = get_reference_count(ea)

            writer.writerow(
                [
                    name,
                    "0x{:X}".format(ea),
                    sym_type,
                    module if module is not None else "",
                    "ida",
                    reason,
                    ref_count,
                ]
            )
            processed_addresses.add(ea)

        # Then, process all named symbols that haven't been processed yet
        for ea, name in idautils.Names():
            if ea not in processed_addresses:
                sym_type = get_symbol_type(ea)
                module = get_symbol_module(ea)
                reason = get_symbol_reason(ea)
                ref_count = get_reference_count(ea)

                writer.writerow(
                    [
                        name,
                        "0x{:X}".format(ea),
                        sym_type,
                        module if module is not None else "",
                        "ida",
                        reason,
                        ref_count,
                    ]
                )

    print(f"Exported UniSymbols to: {output_path}")


def main():
    output_path = ida_kernwin.ask_file(1, "*.csv", "Save UniSymbol CSV file")
    if output_path:
        export_unisymbols(output_path)


if __name__ == "__main__":
    main()
