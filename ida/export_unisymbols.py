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
        return UniSymbolReason.USER_DEFINED
    return UniSymbolReason.AUTO_ANALYSIS

import ida_segment
import ida_nalt
import idaapi
import ida_name

def get_symbol_module(ea):
    # Get the segment the address belongs to
    seg = ida_segment.getseg(ea)
    if seg:
        # Get the segment name
        seg_name = ida_segment.get_segm_name(seg)
        
        # Check if it's an external segment
        if seg.type == idaapi.SEG_XTRN:
            # For external symbols, try to get the import module name
            name = ida_name.get_name(ea)
            if name:
                parts = name.split('_')
                if len(parts) > 1:
                    return parts[0]  # The module name is often the prefix
            return seg_name
        
        # Check if it's in a special segment that might indicate a different module
        if seg_name.startswith('.idata') or seg_name.startswith('.rdata'):
            # This could be an imported function or data
            name = ida_name.get_name(ea)
            if name:
                parts = name.split('_')
                if len(parts) > 1:
                    return parts[0]  # The module name is often the prefix
        
        # If it's not external or in a special segment, it's likely in the main binary
        return None
    
    # If we couldn't get a segment, return None
    return None

def get_reference_count(ea):
    return len(list(idautils.XrefsTo(ea)))

def export_unisymbols(output_path):
    with open(output_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["name", "addr", "type", "module", "source", "reason", "ref_count"])

        for ea, name in idautils.Names():
            sym_type = get_symbol_type(ea)
            module = get_symbol_module(ea)
            reason = get_symbol_reason(ea)
            ref_count = get_reference_count(ea)

            writer.writerow([
                name,
                "0x{:X}".format(ea),
                sym_type,
                module if module is not None else '',  # Empty string if module is None
                "ida",
                reason,
                ref_count
            ])

    print(f"Exported UniSymbols to: {output_path}")

def main():
    output_path = ida_kernwin.ask_file(1, "*.csv", "Save UniSymbol CSV file")
    if output_path:
        export_unisymbols(output_path)

if __name__ == "__main__":
    main()