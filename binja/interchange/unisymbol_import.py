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
        self.symbol_file = symbol_file  # symbol_file is expected to be a string path
        self.log = bv.create_logger("UniSymbol")
        self.log.log_info(
            f"ImportUniSymbolsTask initialized for file: {self.symbol_file}"
        )

    def run(self):
        self.log.log_info("starting unisymbol import process...")
        # read and process symbols from the file
        self.log.log_info(f"reading symbols from {self.symbol_file}")
        uni_symbols = self.read_unisymbols(Path(self.symbol_file))

        if not uni_symbols:
            self.log.log_warn(
                "no symbols found in the file or an error occurred during reading."
            )
            self.finish()
            return

        # define tag types as necessary
        self.create_tag_types()

        self.log.log_info(f"found {len(uni_symbols)} symbols, starting import...")

        # initialize statistics dictionary
        stats = {t: 0 for t in UniSymbol.SymbolType}
        total_imported = 0
        total_external_imported = 0
        total_skipped = 0
        total_user_defined = 0
        total_auto_analysis = 0
        total_redefined = 0

        undo_state = self.bv.begin_undo_actions()
        self.log.log_debug("began undo actions.")

        for i, symbol in enumerate(uni_symbols):
            if self.cancelled:
                self.log.log_warn("import task cancelled by user.")
                break

            self.log.log_debug(
                f"processing symbol {i+1}/{len(uni_symbols)}: {symbol.name} at 0x{symbol.addr:x}"
            )

            is_redefinition = False

            # check for existing symbol at the address
            existing_symbol = self.bv.get_symbol_at(symbol.addr)
            existing_function = None
            containing_funcs = self.bv.get_functions_containing(symbol.addr)

            new_symbol_is_user = symbol.reason == UniSymbol.SymbolReason.USER_DEFINED
            new_symbol_is_high_priority = symbol.priority > 1

            self.log.log_debug(
                f"  new symbol: name='{symbol.name}', addr=0x{symbol.addr:x}, type={symbol.type.name}, reason={symbol.reason.name}, priority={symbol.priority}"
            )
            self.log.log_debug(
                f"  new symbol is_user: {new_symbol_is_user}, is_high_priority: {new_symbol_is_high_priority}"
            )

            if existing_symbol is not None:
                self.log.log_debug(
                    f"  existing symbol found: name='{existing_symbol.name}', type={existing_symbol.type.name}, auto={existing_symbol.auto} at 0x{existing_symbol.address:x}"
                )
                existing_symbol_is_auto = existing_symbol.auto

                if (
                    existing_symbol_is_auto and new_symbol_is_user
                ) or new_symbol_is_high_priority:
                    self.log.log_info(
                        f"  replacing existing {( 'auto' if existing_symbol_is_auto else 'user')} symbol '{existing_symbol.name}' with '{symbol.name}' at 0x{symbol.addr:x} due to {'user definition' if new_symbol_is_user else 'high priority'}."
                    )
                    (
                        self.bv.undefine_auto_symbol(existing_symbol)
                        if existing_symbol.auto
                        else self.bv.undefine_user_symbol(existing_symbol)
                    )
                    is_redefinition = True
                else:
                    self.log.log_debug(
                        f"  skipping '{symbol.name}' at 0x{symbol.addr:x} (already defined as '{existing_symbol.name}', and new symbol does not take precedence)."
                    )
                    total_skipped += 1
                    continue
            else:
                self.log.log_debug(f"  no existing symbol at 0x{symbol.addr:x}.")

            functions_matching_symbol_start_addr = [
                func for func in containing_funcs if func.start == symbol.addr
            ]

            if len(functions_matching_symbol_start_addr) > 0:
                self.log.log_debug(
                    f"  found {len(functions_matching_symbol_start_addr)} function(s) starting at 0x{symbol.addr:x}."
                )
                single_function_matches_symbol = (
                    len(functions_matching_symbol_start_addr) == 1
                )
                if not single_function_matches_symbol:
                    self.log.log_warn(
                        f"  skipping '{symbol.name}' at 0x{symbol.addr:x} (multiple functions start at this address, ambiguous)."
                    )
                    total_skipped += 1
                    continue

                existing_function = functions_matching_symbol_start_addr[0]
                self.log.log_debug(
                    f"  existing function found: name='{existing_function.name}', auto={existing_function.auto} at 0x{existing_function.start:x}"
                )
                existing_func_is_auto = existing_function.auto

                if (
                    existing_func_is_auto and new_symbol_is_user
                ) or new_symbol_is_high_priority:
                    self.log.log_info(
                        f"  existing function '{existing_function.name}' at 0x{symbol.addr:x} will be affected by new symbol '{symbol.name}' due to {'user definition' if new_symbol_is_user else 'high priority'}."
                    )
                    is_redefinition = True
                elif symbol.type in [
                    UniSymbol.SymbolType.FUNCTION,
                    UniSymbol.SymbolType.THUNK_FUNCTION,
                ]:
                    self.log.log_debug(
                        f"  skipping function symbol '{symbol.name}' at 0x{symbol.addr:x} (function '{existing_function.name}' already defined, and new symbol does not take precedence)."
                    )
                    total_skipped += 1
                    continue

            binja_sym_type = self.get_binja_symbol_type(symbol)
            self.log.log_debug(
                f"  determined binja symbol type: {binja_sym_type} for unisymbol type: {symbol.type.name}"
            )

            if binja_sym_type is not None:
                if symbol.type in [
                    UniSymbol.SymbolType.FUNCTION,
                    UniSymbol.SymbolType.THUNK_FUNCTION,
                ]:
                    if existing_function is not None:
                        if (
                            (existing_function.auto and new_symbol_is_user)
                            or new_symbol_is_high_priority
                            or existing_function.name != symbol.name
                        ):
                            self.log.log_debug(
                                f"  updating name of existing function '{existing_function.name}' to '{symbol.name}' at 0x{symbol.addr:x}."
                            )
                            existing_function.name = symbol.name
                    else:
                        self.log.log_debug(
                            f"  creating new user function '{symbol.name}' at 0x{symbol.addr:x}."
                        )
                        current_sym_at_addr = self.bv.get_symbol_at(symbol.addr)
                        if (
                            current_sym_at_addr
                            and current_sym_at_addr.type != SymbolType.FunctionSymbol
                        ):
                            self.log.log_warn(
                                f"  attempting to create function '{symbol.name}' at 0x{symbol.addr:x}, but a non-function symbol '{current_sym_at_addr.name}' of type {current_sym_at_addr.type} still exists. This might lead to issues."
                            )

                        self.bv.create_user_function(symbol.addr)
                        new_func = self.bv.get_function_at(symbol.addr)
                        if new_func is None:
                            self.log.log_error(
                                f"  failed to create user function '{symbol.name}' at 0x{symbol.addr:x}. This may be due to overlapping functions, existing data, or bad code."
                            )
                            total_skipped += 1
                            continue
                        new_func.name = symbol.name
                        self.log.log_debug(
                            f"  successfully created and named new function '{new_func.name}'."
                        )

                binja_sym_namespace = symbol.module if symbol.is_external() else None
                self.log.log_debug(
                    f"  symbol namespace: {binja_sym_namespace if binja_sym_namespace else 'Default (None)'}"
                )

                binja_sym = Symbol(
                    binja_sym_type,
                    symbol.addr,
                    symbol.name,
                    namespace=binja_sym_namespace,
                )
                self.log.log_debug(
                    f"  created binja symbol object: name='{binja_sym.name}', type={binja_sym.type}, addr=0x{binja_sym.address:x}"
                )

                if symbol.reason == UniSymbol.SymbolReason.USER_DEFINED:
                    self.log.log_debug(f"  defining '{symbol.name}' as user symbol.")
                    self.bv.define_user_symbol(binja_sym)
                    self.add_specific_tag(symbol, TAG_OTHER_USER, symbol.summary())
                    total_user_defined += 1
                else:
                    self.log.log_debug(f"  defining '{symbol.name}' as auto symbol.")
                    self.bv.define_auto_symbol(binja_sym)
                    self.add_source_tag(symbol)
                    total_auto_analysis += 1

                self.log.log_info(
                    f"  imported '{symbol.name}' at 0x{symbol.addr:x} as {symbol.type.name} (Binja type: {binja_sym_type.name})."
                )
                stats[symbol.type] += 1
                total_imported += 1

                if symbol.is_external():
                    self.log.log_debug(
                        f"  symbol '{symbol.name}' is external (module: {symbol.module})."
                    )
                    total_external_imported += 1

                if is_redefinition:
                    self.log.log_debug(
                        f"  symbol '{symbol.name}' was a redefinition of a prior symbol/function name."
                    )
                    total_redefined += 1
            else:
                self.log.log_warn(
                    f"  skipping unknown/unmappable unisymbol type {symbol.type.name} for symbol: {symbol.name} at 0x{symbol.addr:x}"
                )
                total_skipped += 1

        self.log.log_debug("finished processing all symbols.")
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
            if count > 0:
                self.log.log_info(f"  {sym_type.name}: {count}")

        self.bv.commit_undo_actions(undo_state)
        self.log.log_debug("committed undo actions.")

        summary_message = (
            f"Total symbols processed: {len(uni_symbols)} ({total_skipped} skipped)\n"
            f"Total symbols imported: {total_imported} ({total_external_imported} external)\n"
            f"Symbol sources: {total_user_defined} user-defined ({total_redefined} redefined), {total_auto_analysis} auto-analysis\n"
            + "\n".join(
                f"  {sym_type.name}: {count}"
                for sym_type, count in stats.items()
                if count > 0
            )
        )
        show_message_box("UniSymbol Import Complete", summary_message)
        self.log.log_info("unisymbol import process finished.")
        self.finish()

    def read_unisymbols(self, input_path: Path) -> List[UniSymbol]:
        self.log.log_debug(f"attempting to read unisymbols from: {input_path}")
        symbols: List[UniSymbol] = []

        if not input_path.exists():
            self.log.log_error(f"input file does not exist: {input_path}")
            return symbols
        if not input_path.is_file():
            self.log.log_error(f"input path is not a file: {input_path}")
            return symbols

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
        self.log.log_debug(
            f"  settings: ida_symbols_force_auto={ida_symbols_force_auto}, ida_symbol_priority={ida_symbol_priority}"
        )
        self.log.log_debug(
            f"  settings: ghidra_symbols_force_auto={ghidra_symbols_force_auto}, ghidra_symbol_priority={ghidra_symbol_priority}"
        )

        def apply_corrections(row: dict, row_num: int) -> Optional[dict]:
            self.log.log_debug(f"  processing csv row {row_num}: {row}")
            original_reason = row.get("reason")
            original_priority = row.get("priority")

            if "priority" not in row or not row["priority"]:
                row["priority"] = "1"

            if row.get("source") == "ida":
                row["priority"] = str(ida_symbol_priority)
                if ida_symbols_force_auto:
                    row["reason"] = UniSymbol.SymbolReason.AUTO_ANALYSIS.name
                self.log.log_debug(
                    f"    ida symbol: original_reason='{original_reason}', new_reason='{row['reason']}'. original_priority='{original_priority}', new_priority='{row['priority']}'"
                )

            if row.get("source") == "ghidra":
                row["priority"] = str(ghidra_symbol_priority)
                if ghidra_symbols_force_auto:
                    row["reason"] = UniSymbol.SymbolReason.AUTO_ANALYSIS.name
                self.log.log_debug(
                    f"    ghidra symbol: original_reason='{original_reason}', new_reason='{row['reason']}'. original_priority='{original_priority}', new_priority='{row['priority']}'"
                )
            return row

        try:
            with open(input_path, mode="r", encoding="utf-8") as csvfile:
                reader = csv.DictReader(csvfile)
                if not reader.fieldnames:
                    self.log.log_error(
                        f"csv file {input_path} is empty or has no header."
                    )
                    return symbols

                self.log.log_debug(f"  csv headers: {reader.fieldnames}")
                expected_fields = ["name", "addr", "type", "module", "source", "reason"]
                missing_fields = [
                    field for field in expected_fields if field not in reader.fieldnames
                ]
                if missing_fields:
                    self.log.log_error(
                        f"  csv file {input_path} is missing expected columns: {missing_fields}. Required: {expected_fields}"
                    )
                    return symbols

                for i, row_data in enumerate(reader):
                    row_num = i + 2
                    corrected_row = dict(row_data)
                    corrected_row = apply_corrections(corrected_row, row_num)

                    if corrected_row is None:
                        self.log.log_warn(
                            f"  row {row_num} skipped by correction logic."
                        )
                        continue

                    addr_val_str = corrected_row.get("addr", "").strip()
                    addr_val = None
                    try:
                        addr_val = int(addr_val_str, 16)
                    except ValueError:
                        self.log.log_warn(
                            f"  invalid address '{addr_val_str}' for symbol '{corrected_row.get('name', 'N/A')}' in row {row_num}. Skipping."
                        )
                        continue

                    try:
                        symbol_type_str = corrected_row["type"]
                        symbol_reason_str = corrected_row["reason"]
                        symbol_type_val = UniSymbol.SymbolType[symbol_type_str]
                        symbol_reason_val = UniSymbol.SymbolReason[symbol_reason_str]
                    except KeyError as e:
                        self.log.log_warn(
                            f"  invalid 'type' ('{symbol_type_str}') or 'reason' ('{symbol_reason_str}') value in row {row_num} for symbol '{corrected_row['name']}': {e}. Skipping."
                        )
                        continue
                    except TypeError as e:
                        self.log.log_warn(
                            f"  missing 'type' or 'reason' value in row {row_num} for symbol '{corrected_row['name']}': {e}. Skipping."
                        )
                        continue

                    symbol = UniSymbol(
                        name=corrected_row["name"],
                        addr=addr_val,
                        type=symbol_type_val,
                        module=(
                            corrected_row["module"] if corrected_row["module"] else None
                        ),
                        source=corrected_row["source"],
                        reason=symbol_reason_val,
                        priority=int(corrected_row.get("priority", 1)),
                    )
                    self.log.log_debug(
                        f"  successfully parsed symbol from row {row_num}: {symbol}"
                    )
                    symbols.append(symbol)
        except FileNotFoundError:
            self.log.log_error(f"file not found: {input_path}")
            return []
        except Exception as e:
            self.log.log_error(
                f"error reading csv file {input_path}: {e}", exc_info=True
            )
            return []

        self.log.log_info(f"finished reading {len(symbols)} symbols from {input_path}.")
        return symbols

    def get_binja_symbol_type(self, symbol: UniSymbol) -> Optional[SymbolType]:
        self.log.log_debug(
            f"  determining binja symbol type for unisymbol: name='{symbol.name}', type={symbol.type.name}, is_external={symbol.is_external()}"
        )
        type_mapping = {
            UniSymbol.SymbolType.FUNCTION: SymbolType.FunctionSymbol,
            UniSymbol.SymbolType.DATA_LABEL: SymbolType.DataSymbol,
            UniSymbol.SymbolType.INSTRUCTION_LABEL: SymbolType.LocalLabelSymbol,
            UniSymbol.SymbolType.THUNK_FUNCTION: SymbolType.FunctionSymbol,
        }

        if symbol.is_external():
            if (
                symbol.type == UniSymbol.SymbolType.FUNCTION
                or symbol.type == UniSymbol.SymbolType.THUNK_FUNCTION
            ):
                self.log.log_debug(
                    "    mapping to ImportedFunctionSymbol (external function/thunk)"
                )
                return SymbolType.ImportedFunctionSymbol
            else:
                self.log.log_debug(
                    "    mapping to ImportedDataSymbol (external data/label)"
                )
                return SymbolType.ImportedDataSymbol

        mapped_type = type_mapping.get(symbol.type)
        if mapped_type:
            self.log.log_debug(
                f"    mapped unisymbol type {symbol.type.name} to binja type {mapped_type.name}"
            )
        else:
            self.log.log_warn(
                f"    no direct binja mapping for unisymbol type {symbol.type.name}"
            )
        return mapped_type

    def create_tag_types(self):
        self.log.log_debug("checking and creating tag types if necessary...")
        all_tag_sources = {**SOURCE_TAG_TYPES, "user_direct": TAG_OTHER_USER}

        for source_key, tag_name in all_tag_sources.items():
            if not self.bv.get_tag_type(tag_name):
                icon_key = source_key
                if source_key == "user_direct":
                    icon_key = "user"

                icon = SOURCE_TAG_ICONS.get(icon_key, "❓")
                self.log.log_info(
                    f"  creating tag type: name='{tag_name}', icon='{icon}' (source_key: {source_key})"
                )
                self.bv.create_tag_type(tag_name, icon)
            else:
                self.log.log_debug(f"  tag type '{tag_name}' already exists.")

    def _tag_exists(self, addr: int, tag_type_name: str) -> bool:
        """helper to check if a specific tag type already exists at an address"""
        # bv.get_tags_at() returns a list of Tag objects
        existing_tags_at_addr = self.bv.get_tags_at(addr)
        for current_tag in existing_tags_at_addr:  # current_tag is a Tag object
            if (
                current_tag.type.name == tag_type_name
            ):  # Access type directly from Tag object
                return True
        return False

    def add_specific_tag(self, symbol: UniSymbol, tag_type_name: str, tag_data: str):
        self.log.log_debug(
            f"  attempting to add specific tag '{tag_type_name}' for symbol: name='{symbol.name}'"
        )
        tag_type_obj = self.bv.get_tag_type(tag_type_name)  # Get the TagType object
        if tag_type_obj:
            if not self._tag_exists(
                symbol.addr, tag_type_name
            ):  # Pass the name for comparison
                self.bv.add_tag(
                    symbol.addr, tag_type_name, tag_data
                )  # Use name or TagType object
                self.log.log_debug(
                    f"    added tag '{tag_type_name}' at 0x{symbol.addr:x} with data: '{tag_data}'"
                )
            else:
                self.log.log_debug(
                    f"    tag '{tag_type_name}' already exists at 0x{symbol.addr:x} for symbol '{symbol.name}'. Skipping."
                )
        else:
            self.log.log_warn(
                f"    failed to add tag for symbol '{symbol.name}'. Tag type '{tag_type_name}' does not exist."
            )

    def add_source_tag(self, symbol: UniSymbol):
        self.log.log_debug(
            f"  attempting to add analysis source tag for symbol: name='{symbol.name}', source='{symbol.source}'"
        )
        source_lower = symbol.source.lower()
        if source_lower in SOURCE_TAG_TYPES and source_lower != "user":
            tag_type_name = SOURCE_TAG_TYPES[source_lower]
            self.add_specific_tag(symbol, tag_type_name, symbol.summary())
        elif source_lower == "user":
            self.log.log_debug(
                f"    symbol source is '{source_lower}', specific user tag handled elsewhere if reason is USER_DEFINED."
            )
        else:
            self.log.log_warn(
                f"    unknown analysis source '{symbol.source}' for symbol '{symbol.name}'. No specific source tag added by this function."
            )


def import_unisymbols(bv: BinaryView):
    # prompt user to select the unisymbol csv file
    symbol_file = get_open_filename_input(
        "Select UniSymbol CSV file", "CSV Files (*.csv)"
    )

    if symbol_file is None:
        return

    # create and run the import task
    task = ImportUniSymbolsTask(bv, symbol_file)
    task.run()


PluginCommand.register(
    "UniSymbol\\Import UniSymbols",
    "Import symbols from a UniSymbol CSV file.",
    import_unisymbols,
)
