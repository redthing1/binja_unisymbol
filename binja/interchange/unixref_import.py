import csv
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass
from enum import Enum

from binaryninja import *

from ..models import UniXref
from ..settings import my_settings


class ImportUniXrefsTask(BackgroundTask):
    def __init__(self, bv: BinaryView, xref_file: str):
        BackgroundTask.__init__(self, "Importing UniXrefs...", can_cancel=True)
        self.bv = bv
        self.xref_file = xref_file
        self.log = bv.create_logger("UniSymbol")

    def run(self):
        # read and process xrefs from the file
        self.log.log_info(f"reading xrefs from {self.xref_file}")
        uni_xrefs = self.read_unixrefs(Path(self.xref_file))

        self.log.log_info(f"found {len(uni_xrefs)} xrefs, importing...")

        # initialize statistics
        stats = {t.name: 0 for t in UniXref.ReferenceType}
        total_imported = 0
        total_skipped = 0

        undo_state = self.bv.begin_undo_actions()

        for xref in uni_xrefs:
            if self.cancelled:
                break

            try:
                if xref.ref_type in [
                    UniXref.ReferenceType.DATA_READ,
                    UniXref.ReferenceType.DATA_WRITE,
                ]:
                    # check if the reference already exists
                    existing_data_refs = self.bv.get_data_refs_from(xref.from_addr)
                    if xref.to_addr in existing_data_refs:
                        total_skipped += 1
                        continue
                    existing_code_refs = self.bv.get_code_refs_from(xref.from_addr)
                    if xref.to_addr in existing_code_refs:
                        total_skipped += 1
                        continue

                    # determine if the reference is from data or code
                    if self.bv.get_data_var_at(xref.from_addr) is not None:
                        self.bv.add_user_data_ref(xref.from_addr, xref.to_addr)
                    elif self.bv.get_function_at(xref.from_addr) is not None:
                        func = self.bv.get_function_at(xref.from_addr)
                        func.add_user_code_ref(xref.from_addr, xref.to_addr)
                    else:
                        raise ValueError(
                            f"from address is not data or code: 0x{xref.from_addr:x}"
                        )

                elif xref.ref_type == UniXref.ReferenceType.CALL:
                    # ignore calls across modules
                    if xref.from_module != xref.to_module:
                        raise ValueError(
                            f"cross-module calls are not supported ({xref.from_module} -> {xref.to_module})"
                        )

                    # check if the reference already exists
                    existing_code_refs = self.bv.get_code_refs_from(xref.from_addr)
                    if xref.to_addr in existing_code_refs:
                        total_skipped += 1
                        continue

                    # get the function at the from address
                    target_func = self.bv.get_function_at(xref.to_addr)
                    if target_func is None:
                        raise ValueError(f"target function not found: {xref.to_addr:x}")

                    target_func.add_user_code_ref(xref.from_addr, xref.to_addr)
                elif xref.ref_type == UniXref.ReferenceType.JUMP:
                    # ignore jumps
                    total_skipped += 1
                    continue
                elif xref.ref_type in [
                    UniXref.ReferenceType.IMPORT,
                    UniXref.ReferenceType.EXPORT,
                ]:
                    # ignore imports and exports
                    total_skipped += 1
                    continue
                elif xref.ref_type == UniXref.ReferenceType.UNKNOWN:
                    # ignore unknown references
                    total_skipped += 1
                    continue
                else:
                    raise NotImplementedError(f"not supported: {xref.ref_type}")

                # log successful import and update statistics
                self.log.log_debug(
                    f"imported xref: 0x{xref.from_addr:x} -> 0x{xref.to_addr:x} ({xref.ref_type.name})"
                )

                stats[xref.ref_type.name] += 1
                total_imported += 1
            except Exception as e:
                self.log.log_error(
                    f"failed to import xref: 0x{xref.from_addr:x} -> 0x{xref.to_addr:x}. error: {str(e)}"
                )
                total_skipped += 1

        # log final statistics
        self.log.log_info(
            f"total xrefs processed: {len(uni_xrefs)} ({total_skipped} skipped)"
        )
        self.log.log_info(f"total xrefs imported: {total_imported}")
        for ref_type, count in stats.items():
            self.log.log_info(f"  {ref_type}: {count}")
        
        self.bv.commit_undo_actions(undo_state)

        # Show a message box with the final statistics
        show_message_box(
            "UniXref Import",
            f"Total xrefs processed: {len(uni_xrefs)} ({total_skipped} skipped)\n"
            f"Total xrefs imported: {total_imported}\n"
            + "\n".join(f"  {ref_type}: {count}" for ref_type, count in stats.items()),
        )

        # Mark finished
        self.finish()

    def read_unixrefs(self, input_path: Path) -> List[UniXref]:
        xrefs = []
        with open(input_path) as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                # skip rows with invalid data (negative addresses, etc.)
                if "-" in row["from_addr"] or "-" in row["to_addr"]:
                    continue

                xref = UniXref(
                    from_addr=int(row["from_addr"], 16),
                    to_addr=int(row["to_addr"], 16),
                    ref_type=UniXref.ReferenceType[row["ref_type"]],
                    from_module=row["from_module"] if row["from_module"] else None,
                    to_module=row["to_module"] if row["to_module"] else None,
                    from_symbol=row["from_symbol"] if row["from_symbol"] else None,
                    to_symbol=row["to_symbol"] if row["to_symbol"] else None,
                )

                xrefs.append(xref)
        return xrefs


def import_unixrefs(bv: BinaryView):
    xref_file = get_open_filename_input("Select UniXref CSV file", "CSV Files (*.csv)")

    if xref_file is None:
        return

    ImportUniXrefsTask(bv, xref_file).run()


PluginCommand.register(
    "UniSymbol\\Import UniXrefs",
    "Import cross-references from a UniXref CSV file.",
    import_unixrefs,
)
