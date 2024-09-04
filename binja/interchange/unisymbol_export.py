from binaryninja import *
import csv
from pathlib import Path

from ..models import UniSymbol, GhidraSymbol


def get_symbol_type(symbol):
    if symbol.type == SymbolType.FunctionSymbol:
        return UniSymbol.SymbolType.FUNCTION
    elif symbol.type == SymbolType.ImportedFunctionSymbol:
        return UniSymbol.SymbolType.FUNCTION
    elif symbol.type == SymbolType.DataSymbol:
        return UniSymbol.SymbolType.DATA_LABEL
    elif symbol.type == SymbolType.ImportedDataSymbol:
        return UniSymbol.SymbolType.DATA_LABEL
    elif symbol.type == SymbolType.LocalLabelSymbol:
        return UniSymbol.SymbolType.INSTRUCTION_LABEL
    else:
        return UniSymbol.SymbolType.UNKNOWN


def get_symbol_reason(symbol):
    return (
        UniSymbol.SymbolReason.USER_DEFINED
        if not symbol.auto
        else UniSymbol.SymbolReason.AUTO_ANALYSIS
    )


def export_unicsv(log: Logger, bv: BinaryView, output_path: Path):
    uni_symbols = []

    for symbol in bv.get_symbols():
        module_name = None
        if symbol.type in [
            SymbolType.ImportedFunctionSymbol,
            SymbolType.ImportedDataSymbol,
        ]:
            module_name = symbol.namespace

        uni_symbol = UniSymbol(
            name=symbol.name,
            addr=symbol.address,
            type=get_symbol_type(symbol),
            module=module_name,
            source="binja",
            reason=get_symbol_reason(symbol),
        )
        uni_symbols.append(uni_symbol)

    uni_symbols = sorted(uni_symbols, key=lambda x: x.addr)

    with open(output_path, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["name", "addr", "type", "module", "source", "reason"])
        for symbol in uni_symbols:
            writer.writerow(
                [
                    symbol.name,
                    hex(symbol.addr),
                    symbol.type.name,  # Use enum name instead of value
                    (
                        symbol.module if symbol.module else ""
                    ),  # Use empty string instead of 'None'
                    symbol.source,
                    symbol.reason.name,  # Use enum name instead of value
                ]
            )

    log.log_info(f"exported {len(uni_symbols)} symbols to {output_path}")


class ExportUniSymbolsTask(BackgroundTask):
    def __init__(self, bv: BinaryView, output_file: str):
        BackgroundTask.__init__(self, "Exporting UniSymbols...", can_cancel=True)
        self.bv = bv
        self.output_file = output_file
        self.log = bv.create_logger("UniSymbolExport")

    def run(self):
        export_unicsv(self.log, self.bv, Path(self.output_file))
        self.log.log_info(f"UniSymbols exported to {self.output_file}")


def export_unisymbols_to_csv(bv: BinaryView):
    output_file = get_save_filename_input("Export UniSymbols", "CSV Files (*.csv)")
    if output_file:
        ExportUniSymbolsTask(bv, output_file).run()


PluginCommand.register(
    "UniSymbol\\Export Unified Symbols",
    "Export symbols in UniSymbol CSV format.",
    export_unisymbols_to_csv,
)
