import csv

from binaryninja import *

from .models import GhidraSymbol, UniSymbol


def read_ghidra_symbols(input_path: Path) -> List[GhidraSymbol]:
    """read symbols from the ghidra-exported csv file"""
    symbols = []
    with open(input_path) as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            symbol = GhidraSymbol(
                name=row["Name"],
                loc=row["Location"],
                type=row["Type"],
                namespace=row["Namespace"],
                source=row["Source"],
                ref_count=int(row["Reference Count"]),
            )
            symbols.append(symbol)
    return symbols


def filter_importable_symbols(symbols: List[GhidraSymbol]) -> List[GhidraSymbol]:
    """filter out symbols that are not importable"""
    return [symbol for symbol in symbols if not (symbol.is_unknown())]


def convert_ghidra_symbols_to_uni_symbols(
    bv: BinaryView,
    gh_symbols: List[GhidraSymbol],
) -> List[UniSymbol]:
    """convert ghidra symbols to unified symbols"""
    uni_symbols = []
    for gh_symbol in gh_symbols:
        # reformat default function names
        name = gh_symbol.name
        if re.match(r"FUN_[0-9a-f]{8}", name):
            name = f"fun_{name[4:].lower()}"

        module_name = None

        # parse the address and module name
        if gh_symbol.is_external():
            # get module name from the namespace
            ext_module_name = gh_symbol.namespace
            # parse the location string
            external_loc = re.search(r"\[(.+)\]", gh_symbol.loc)
            try:
                addr = int(external_loc.group(1), 16)
            except ValueError:
                # probably an unknown external address
                log_debug(
                    f"skipping ghidra symbol with unknown external address: {gh_symbol.name} @ {gh_symbol.loc}"
                )
                continue
            module_name = ext_module_name
        elif gh_symbol.is_within_current_module():
            # symbol in main binary
            addr = int(gh_symbol.loc, 16)
            # # assign module name to current binary
            # module_name = bv.file.filename
        else:
            # a different type of symbol we don't know how to handle
            log_warn(
                f"skipping ghidra symbol with unusable location: {gh_symbol.name} @ {gh_symbol.loc}"
            )
            continue

        # assign symbol type
        if gh_symbol.is_function():
            sym_type = UniSymbol.SymbolType.FUNCTION
        elif gh_symbol.is_instruction_label():
            sym_type = UniSymbol.SymbolType.INSTRUCTION_LABEL
        elif gh_symbol.is_data_label():
            sym_type = UniSymbol.SymbolType.DATA_LABEL
        elif gh_symbol.is_thunk_function():
            sym_type = UniSymbol.SymbolType.THUNK_FUNCTION
        else:
            sym_type = UniSymbol.SymbolType.UNKNOWN

        sym_reason = UniSymbol.SymbolReason.AUTO_ANALYSIS
        if gh_symbol.is_user_defined():
            sym_reason = UniSymbol.SymbolReason.USER_DEFINED

        uni_symbols.append(
            UniSymbol(
                name=name,
                addr=addr,
                type=sym_type,
                module=module_name,
                source="ghidra",
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

    if symbol.is_external():
        return (
            SymbolType.ImportedFunctionSymbol
            if symbol.type == UniSymbol.SymbolType.FUNCTION
            else SymbolType.ImportedDataSymbol
        )

    return type_mapping.get(symbol.type)


TAG_GHIDRA = "Ghidra"
TAG_OTHER_USER = "Other User"


class ImportGhidraSymbolsTask(BackgroundTask):
    def __init__(self, bv: BinaryView, symbol_file: str):
        BackgroundTask.__init__(self, "Importing ghidra symbols...", can_cancel=True)
        self.bv = bv
        self.symbol_file = symbol_file
        self.log = bv.create_logger("GhidraUtils")

    def run(self):
        # read and process symbols from the file
        self.log.log_info(f"reading symbols from {self.symbol_file}")
        symbols = read_ghidra_symbols(Path(self.symbol_file))
        filtered_symbols = filter_importable_symbols(symbols)
        uni_symbols = convert_ghidra_symbols_to_uni_symbols(self.bv, filtered_symbols)

        # define tag types as necessary
        if not self.bv.get_tag_type(TAG_GHIDRA):
            self.bv.create_tag_type(TAG_GHIDRA, "🐲")
        if not self.bv.get_tag_type(TAG_OTHER_USER):
            self.bv.create_tag_type(TAG_OTHER_USER, "👤")

        self.log.log_info(f"found {len(uni_symbols)} importable symbols, importing...")

        # initialize statistics dictionary
        stats: Dict[UniSymbol.SymbolType, int] = {t: 0 for t in UniSymbol.SymbolType}
        total_imported = 0
        total_external_imported = 0
        total_skipped = 0
        total_user_defined = 0
        total_auto_analysis = 0
        total_redefined = 0

        for symbol in uni_symbols:
            if self.cancelled:
                break

            # check for existing symbol at the address
            existing_symbol = self.bv.get_symbol_at(symbol.addr)
            is_redefiniton = False

            if existing_symbol is not None:
                # check if the symbol there is automatically generated
                # and if the ghidra symbol is user-defined
                if (
                    existing_symbol.auto
                    and symbol.reason == UniSymbol.SymbolReason.USER_DEFINED
                ):
                    # remove the existing symbol
                    self.bv.undefine_auto_symbol(existing_symbol)
                    is_redefiniton = True
                else:
                    # skip; the symbol already here takes precedence
                    self.log.log_debug(
                        f"skipping {symbol.name} at 0x{symbol.addr:x} (already defined)"
                    )
                    total_skipped += 1
                    continue

            # create appropriate definition based on symbol type
            binja_sym = None
            binja_sym_type = get_binja_symbol_type(symbol)

            if binja_sym_type is not None:
                # if it's a function, mark the region as a function
                if symbol.type in [
                    UniSymbol.SymbolType.FUNCTION,
                    UniSymbol.SymbolType.THUNK_FUNCTION,
                ]:
                    self.bv.create_user_function(symbol.addr)

                binja_sym_namespace = symbol.module if symbol.is_external() else None
                binja_sym = Symbol(
                    binja_sym_type,
                    symbol.addr,
                    symbol.name,
                    namespace=binja_sym_namespace,
                )
            else:
                # ??? unknown symbol type
                self.log.log_warn(
                    f"skipping unknown symbol type {symbol.type}: {symbol}"
                )
                total_skipped += 1
                continue

            if binja_sym is not None:
                if symbol.reason == UniSymbol.SymbolReason.USER_DEFINED:
                    self.bv.define_user_symbol(binja_sym)
                    self.bv.add_tag(symbol.addr, TAG_OTHER_USER, symbol.summary())
                    total_user_defined += 1
                else:
                    self.bv.define_auto_symbol(binja_sym)
                    self.bv.add_tag(symbol.addr, TAG_GHIDRA, symbol.summary())
                    total_auto_analysis += 1

                # log successful import and update statistics
                self.log.log_debug(
                    f"imported {symbol.name} at 0x{symbol.addr:x} as {symbol.type.name}"
                )
                stats[symbol.type] += 1
                total_imported += 1

                if symbol.is_external():
                    total_external_imported += 1

                if is_redefiniton:
                    total_redefined += 1

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

        # notify user of completion
        # show a message box with the final statistics
        show_message_box(
            "Ghidra Symbols Import",
            f"Total symbols processed: {len(uni_symbols)} ({total_skipped} skipped)\n"
            f"Total symbols imported: {total_imported} ({total_external_imported} external)\n"
            f"Symbol sources: {total_user_defined} user-defined ({total_redefined} redefined), {total_auto_analysis} auto-analysis\n"
            + "\n".join(
                f"  {sym_type.name}: {count}" for sym_type, count in stats.items()
            ),
        )

        # mark finished
        self.finish()


def import_ghidra_symbols(bv: BinaryView):
    # prompt user to select the ghidra-exported csv file
    symbol_file = get_open_filename_input(
        "Select Ghidra-exported CSV file", "CSV Files (*.csv)"
    )

    if symbol_file is None:
        return

    # create and run the import task
    ImportGhidraSymbolsTask(bv, symbol_file).run()


PluginCommand.register(
    "Ghidra\\Import Symbols (CSV)",
    "Import symbols from a Ghidra-exported CSV file.",
    import_ghidra_symbols,
)
