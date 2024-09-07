import csv
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass
from enum import Enum

from binaryninja import *

from ..models import UniSymbol
from ..settings import my_settings


# define tags based on analysis source
TAG_BINJA = "Binja"
TAG_GHIDRA = "Ghidra"
TAG_IDA = "IDA"
TAG_OTHER_USER = "User"
SOURCE_TAG_TYPES = {
    "binja": TAG_BINJA,
    "ghidra": TAG_GHIDRA,
    "ida": TAG_IDA,
    "user": TAG_OTHER_USER,
}
SOURCE_TAG_ICONS = {
    "binja": "🍶",
    "ghidra": "🐲",
    "ida": "🔬",
    "user": "👤",
}


class ImportUniSymbolsTask(BackgroundTask):
    def __init__(self, bv: BinaryView, symbol_file: str):
        BackgroundTask.__init__(self, "importing unisymbols...", can_cancel=True)
        self.bv = bv
        self.symbol_file = symbol_file
        self.log = bv.create_logger("UniSymbol")

    def run(self):
        # read and process symbols from the file
        self.log.log_info(f"reading symbols from {self.symbol_file}")
        uni_symbols = self.read_unisymbols(Path(self.symbol_file))

        # define tag types as necessary
        self.create_tag_types()

        self.log.log_info(f"found {len(uni_symbols)} symbols, importing...")

        # initialize statistics dictionary
        stats = {t: 0 for t in UniSymbol.SymbolType}
        total_imported = 0
        total_external_imported = 0
        total_skipped = 0
        total_user_defined = 0
        total_auto_analysis = 0
        total_redefined = 0

        undo_state = self.bv.begin_undo_actions()

        for symbol in uni_symbols:
            if self.cancelled:
                break

            is_redefinition = False

            # check for existing symbol at the address
            existing_symbol = self.bv.get_symbol_at(symbol.addr)
            existing_function = None
            containing_funcs = self.bv.get_functions_containing(symbol.addr)

            new_symbol_is_user = symbol.reason == UniSymbol.SymbolReason.USER_DEFINED
            new_symbol_is_high_priority = symbol.priority > 1

            # if a symbol already exists at the address, check if it should be replaced
            if existing_symbol is not None:
                existing_symbol_is_auto = existing_symbol.auto

                if (
                    existing_symbol_is_auto and new_symbol_is_user
                ) or new_symbol_is_high_priority:
                    # remove the existing symbol
                    self.bv.undefine_auto_symbol(existing_symbol)
                    is_redefinition = True
                else:
                    # ignore the new symbol; the symbol already here takes precedence
                    self.log.log_debug(
                        f"skipping {symbol.name} at 0x{symbol.addr:x} (already defined)"
                    )
                    total_skipped += 1
                    continue

            # check what functions start at this address
            functions_matching_symbol = [
                func for func in containing_funcs if func.start == symbol.addr
            ]
            if len(functions_matching_symbol) > 0:
                single_function_matches_symbol = len(functions_matching_symbol) == 1
                # if multiple functions match the address, skip the symbol; we can't handle this
                if not single_function_matches_symbol:
                    self.log.log_warn(
                        f"skipping {symbol.name} at 0x{symbol.addr:x} (multiple functions start at this address)"
                    )
                    total_skipped += 1
                    continue

                # there is already a function at this address, determine if it should be replaced
                existing_function = functions_matching_symbol[0]
                existing_func_is_auto = existing_function.auto

                if (
                    existing_func_is_auto and new_symbol_is_user
                ) or new_symbol_is_high_priority:
                    # we should replace the existing function
                    is_redefinition = True
                    # we have stored existing_function
                    # it will be updated instead of removed and redefined
                else:
                    # ignore the new symbol; the function already here takes precedence
                    self.log.log_debug(
                        f"skipping {symbol.name} at 0x{symbol.addr:x} (already defined as function)"
                    )
                    total_skipped += 1
                    continue

            # create appropriate definition based on symbol type
            binja_sym_type = self.get_binja_symbol_type(symbol)

            if binja_sym_type is not None:
                # if it's a function, mark the region as a function
                if symbol.type in [
                    UniSymbol.SymbolType.FUNCTION,
                    UniSymbol.SymbolType.THUNK_FUNCTION,
                ]:
                    if existing_function is not None:
                        # a function is already defined here; update the existing function
                        existing_function.name = symbol.name
                    else:
                        # define a function at the address
                        new_func = self.bv.create_user_function(symbol.addr)
                        new_func.name = symbol.name

                binja_sym_namespace = symbol.module if symbol.is_external() else None
                binja_sym = Symbol(
                    binja_sym_type,
                    symbol.addr,
                    symbol.name,
                    namespace=binja_sym_namespace,
                )

                if symbol.reason == UniSymbol.SymbolReason.USER_DEFINED:
                    self.bv.define_user_symbol(binja_sym)
                    self.bv.add_tag(symbol.addr, TAG_OTHER_USER, symbol.summary())
                    total_user_defined += 1
                else:
                    self.bv.define_auto_symbol(binja_sym)
                    self.add_source_tag(symbol)
                    total_auto_analysis += 1

                # log successful import and update statistics
                self.log.log_debug(
                    f"imported {symbol.name} at 0x{symbol.addr:x} as {symbol.type.name}"
                )
                stats[symbol.type] += 1
                total_imported += 1

                if symbol.is_external():
                    total_external_imported += 1

                if is_redefinition:
                    total_redefined += 1
            else:
                # unknown symbol type
                self.log.log_warn(
                    f"skipping unknown symbol type {symbol.type}: {symbol}"
                )
                total_skipped += 1

        # log final statistics
        self.log.log_info(
            f"total symbols processed: {len(uni_symbols)} ({total_skipped} skipped)"
        )
        self.log.log_info(
            f"total symbols imported: {total_imported} ({total_external_imported} external)"
        )
        self.log.log_info(
            f"symbol sources: {total_user_defined} user ({total_redefined} redefined), {total_auto_analysis} auto"
        )
        for sym_type, count in stats.items():
            self.log.log_info(f"  {sym_type.name}: {count}")
        
        self.bv.commit_undo_actions(undo_state)

        # show a message box with the final statistics
        show_message_box(
            "UniSymbol Import",
            f"Total symbols processed: {len(uni_symbols)} ({total_skipped} skipped)\n"
            f"Total symbols imported: {total_imported} ({total_external_imported} external)\n"
            f"Symbol sources: {total_user_defined} user-defined ({total_redefined} redefined), {total_auto_analysis} auto-analysis\n"
            + "\n".join(
                f"  {sym_type.name}: {count}" for sym_type, count in stats.items()
            ),
        )

        # mark finished
        self.finish()

    def read_unisymbols(self, input_path: Path) -> List[UniSymbol]:
        """read symbols from the unisymbol csv file"""
        symbols = []

        ida_symbols_force_auto = my_settings.get_bool(
            "unisymbol.ida_symbols_as_auto_analysis", self.bv
        )
        ida_symbol_priority = my_settings.get_integer(
            "unisymbol.ida_symbol_priority", self.bv
        )
        ghidra_symbols_force_auto = my_settings.get_bool(
            "unisymbol.ghidra_symbols_as_auto_analysis", self.bv
        )
        ghidra_symbol_priority = my_settings.get_integer(
            "unisymbol.ghidra_symbol_priority", self.bv
        )

        def apply_corrections(row: dict):
            if row["source"] == "ida":
                row["priority"] = ida_symbol_priority
                if ida_symbols_force_auto:
                    row["reason"] = UniSymbol.SymbolReason.AUTO_ANALYSIS.name

            if row["source"] == "ghidra":
                row["priority"] = ghidra_symbol_priority
                if ghidra_symbols_force_auto:
                    row["reason"] = UniSymbol.SymbolReason.AUTO_ANALYSIS.name

            return row

        with open(input_path) as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                row = apply_corrections(row)

                symbol = UniSymbol(
                    name=row["name"],
                    addr=int(row["addr"], 16),
                    type=UniSymbol.SymbolType[row["type"]],
                    module=row["module"] if row["module"] else None,
                    source=row["source"],
                    reason=UniSymbol.SymbolReason[row["reason"]],
                    priority=int(row.get("priority", 1)),
                )

                symbols.append(symbol)
        return symbols

    def get_binja_symbol_type(self, symbol: UniSymbol):
        type_mapping = {
            UniSymbol.SymbolType.FUNCTION: SymbolType.FunctionSymbol,
            UniSymbol.SymbolType.DATA_LABEL: SymbolType.DataSymbol,
            UniSymbol.SymbolType.INSTRUCTION_LABEL: SymbolType.LocalLabelSymbol,
            UniSymbol.SymbolType.THUNK_FUNCTION: SymbolType.FunctionSymbol,
        }

        if symbol.is_external():
            return (
                SymbolType.ImportedFunctionSymbol
                if symbol.type == UniSymbol.SymbolType.FUNCTION
                else SymbolType.ImportedDataSymbol
            )

        return type_mapping.get(symbol.type)

    def create_tag_types(self):
        """create tag types if they don't exist"""
        for source, tag_type in SOURCE_TAG_TYPES.items():
            if not self.bv.get_tag_type(tag_type):
                icon = SOURCE_TAG_ICONS[source]
                self.bv.create_tag_type(tag_type, icon)

    def add_source_tag(self, symbol: UniSymbol):
        """add a tag based on the symbol source"""
        source = symbol.source.lower()
        if source in SOURCE_TAG_TYPES:
            tag_type = SOURCE_TAG_TYPES[source]
            self.bv.add_tag(symbol.addr, tag_type, symbol.summary())
        else:
            self.log.log_warn(f"unknown source for symbol: {symbol.source}")


def import_unisymbols(bv: BinaryView):
    # prompt user to select the unisymbol csv file
    symbol_file = get_open_filename_input(
        "Select UniSymbol CSV file", "CSV Files (*.csv)"
    )

    if symbol_file is None:
        return

    # create and run the import task
    ImportUniSymbolsTask(bv, symbol_file).run()


PluginCommand.register(
    "UniSymbol\\Import UniSymbols",
    "Import symbols from a UniSymbol CSV file.",
    import_unisymbols,
)
