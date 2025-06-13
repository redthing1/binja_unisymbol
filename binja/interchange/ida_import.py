import re
import sys
from pathlib import Path

from binaryninja import *

from ..models import IdaMapSymbol, UniSymbol
from ...claude.ida_map_parser import MapFileParser


def read_ida_map_symbols(input_path: Path) -> List[IdaMapSymbol]:
    """read symbols from the IDA-exported MAP file"""
    parser = MapFileParser()
    map_file = parser.parse_file(str(input_path))
    
    ida_symbols = []
    for symbol in map_file.symbols:
        ida_symbol = IdaMapSymbol(
            segment_id=symbol.segment_id,
            offset=symbol.offset,
            name=symbol.name,
        )
        ida_symbols.append(ida_symbol)
    
    return ida_symbols


def filter_importable_ida_symbols(symbols: List[IdaMapSymbol]) -> List[IdaMapSymbol]:
    """filter out symbols that are not importable"""
    # Filter out common auto-generated symbols that are not useful
    filtered = []
    for symbol in symbols:
        name = symbol.name.lower()
        # Skip common auto-generated symbols
        if (name.startswith('def_') or 
            name.startswith('jpt_') or
            name.startswith('nullsub_') or
            name.startswith('sub_') or
            name.startswith('loc_') or
            name.startswith('unk_') or
            name.startswith('.') or
            name == ''):
            continue
        filtered.append(symbol)
    
    return filtered


def convert_ida_map_symbols_to_uni_symbols(
    bv: BinaryView,
    ida_symbols: List[IdaMapSymbol],
) -> List[UniSymbol]:
    """convert IDA MAP symbols to unified symbols"""
    uni_symbols = []
    
    for ida_symbol in ida_symbols:
        # Calculate linear address from segmented address
        # For most modern binaries, we can use the offset directly
        # as the linear address within the binary
        addr = ida_symbol.offset
        
        # Determine symbol type based on name patterns
        name = ida_symbol.name
        if (name.startswith('sub_') or 
            name.startswith('fun_') or
            name.endswith('_func') or
            '_func_' in name):
            sym_type = UniSymbol.SymbolType.FUNCTION
        elif (name.startswith('dword_') or 
              name.startswith('byte_') or
              name.startswith('word_') or
              name.startswith('qword_') or
              name.startswith('str_') or
              name.startswith('data_')):
            sym_type = UniSymbol.SymbolType.DATA_LABEL
        else:
            # Default to function for most named symbols
            sym_type = UniSymbol.SymbolType.FUNCTION
        
        # All IDA MAP symbols are considered auto-analysis
        sym_reason = UniSymbol.SymbolReason.AUTO_ANALYSIS
        
        uni_symbols.append(
            UniSymbol(
                name=name,
                addr=addr,
                type=sym_type,
                module=None,  # MAP symbols are from main binary
                source="ida_map",
                reason=sym_reason,
            )
        )
    
    return sorted(uni_symbols, key=lambda x: x.addr)


def get_binja_symbol_type(symbol):
    type_mapping = {
        UniSymbol.SymbolType.FUNCTION: SymbolType.FunctionSymbol,
        UniSymbol.SymbolType.DATA_LABEL: SymbolType.DataSymbol,
        UniSymbol.SymbolType.INSTRUCTION_LABEL: SymbolType.LocalLabelSymbol,
        UniSymbol.SymbolType.THUNK_FUNCTION: SymbolType.FunctionSymbol,
    }
    
    return type_mapping.get(symbol.type)


TAG_IDA_MAP = "IDA MAP"


class ImportIdaMapSymbolsTask(BackgroundTask):
    def __init__(self, bv: BinaryView, symbol_file: str):
        BackgroundTask.__init__(self, "Importing IDA MAP symbols...", can_cancel=True)
        self.bv = bv
        self.symbol_file = symbol_file
        self.log = bv.create_logger("UniSymbol")

    def run(self):
        # read and process symbols from the file
        self.log.log_info(f"reading symbols from {self.symbol_file}")
        ida_symbols = read_ida_map_symbols(Path(self.symbol_file))
        filtered_symbols = filter_importable_ida_symbols(ida_symbols)
        uni_symbols = convert_ida_map_symbols_to_uni_symbols(self.bv, filtered_symbols)

        # define tag types as necessary
        if not self.bv.get_tag_type(TAG_IDA_MAP):
            self.bv.create_tag_type(TAG_IDA_MAP, "🔥")

        self.log.log_info(f"found {len(uni_symbols)} importable symbols, importing...")

        # initialize statistics dictionary
        stats: Dict[UniSymbol.SymbolType, int] = {t: 0 for t in UniSymbol.SymbolType}
        total_imported = 0
        total_skipped = 0
        total_user_protected = 0

        # Check settings for user symbol protection
        from ..settings import my_settings
        allow_overwrite_user = my_settings.get_bool("unisymbol.ida_map_allow_overwrite_user", self.bv)

        for symbol in uni_symbols:
            if self.cancelled:
                break

            # check for existing symbol at the address
            existing_symbol = self.bv.get_symbol_at(symbol.addr)

            if existing_symbol is not None:
                # Check if existing symbol is user-defined
                if not existing_symbol.auto and not allow_overwrite_user:
                    # Skip; user-defined symbols are protected
                    self.log.log_debug(
                        f"skipping {symbol.name} at 0x{symbol.addr:x} (user-defined symbol protected)"
                    )
                    total_user_protected += 1
                    continue
                elif existing_symbol.auto:
                    # Remove the existing auto symbol
                    self.bv.undefine_auto_symbol(existing_symbol)
                else:
                    # User symbol and overwrite is allowed
                    self.bv.undefine_user_symbol(existing_symbol)

            # create appropriate definition based on symbol type
            binja_sym = None
            binja_sym_type = get_binja_symbol_type(symbol)

            if binja_sym_type is not None:
                # if it's a function, mark the region as a function
                if symbol.type in [
                    UniSymbol.SymbolType.FUNCTION,
                    UniSymbol.SymbolType.THUNK_FUNCTION,
                ]:
                    self.bv.add_function(symbol.addr, auto_discovered=True)

                binja_sym = Symbol(
                    binja_sym_type,
                    symbol.addr,
                    symbol.name,
                )
            else:
                # unknown symbol type
                self.log.log_warn(
                    f"skipping unknown symbol type {symbol.type}: {symbol}"
                )
                total_skipped += 1
                continue

            if binja_sym is not None:
                # All IDA MAP symbols are treated as auto-analysis
                self.bv.define_auto_symbol(binja_sym)
                self.bv.add_tag(symbol.addr, TAG_IDA_MAP, symbol.summary())

                # log successful import and update statistics
                self.log.log_debug(
                    f"imported {symbol.name} at 0x{symbol.addr:x} as {symbol.type.name}"
                )
                stats[symbol.type] += 1
                total_imported += 1

        # log final statistics
        self.log.log_info(
            f"total symbols processed: {len(uni_symbols)} ({total_skipped} skipped, {total_user_protected} user-protected)"
        )
        self.log.log_info(f"total symbols imported: {total_imported}")
        for sym_type, count in stats.items():
            if count > 0:
                self.log.log_info(f"  {sym_type.name}: {count}")

        # notify user of completion
        show_message_box(
            "IDA MAP Symbols Import",
            f"Total symbols processed: {len(uni_symbols)}\n"
            f"Total symbols imported: {total_imported}\n"
            f"Skipped: {total_skipped}\n"
            f"User-defined symbols protected: {total_user_protected}\n"
            + "\n".join(
                f"  {sym_type.name}: {count}" for sym_type, count in stats.items() if count > 0
            ),
        )

        # mark finished
        self.finish()


def import_ida_map_symbols(bv: BinaryView):
    # prompt user to select the IDA-exported MAP file
    symbol_file = get_open_filename_input(
        "Select IDA-exported MAP file", "MAP Files (*.map)"
    )

    if symbol_file is None:
        return

    # create and run the import task
    ImportIdaMapSymbolsTask(bv, symbol_file).run()


PluginCommand.register(
    "UniSymbol\\Import IDA MAP Symbols",
    "Import symbols from an IDA-exported MAP file.",
    import_ida_map_symbols,
)