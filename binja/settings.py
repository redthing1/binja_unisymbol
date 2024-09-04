import json

from binaryninja.settings import Settings

my_settings = Settings()
my_settings.register_group("unisymbol", "UniSymbol")

# bool: enable legacy importers (import non-UniSymbol from other tools)
my_settings.register_setting(
    "unisymbol.enable_legacy_importers",
    json.dumps(
        {
            "title": "Enable Legacy Importers",
            "description": "Enable importers for non-UniSymbol data from other tools (e.g. Ghidra, IDA)",
            "default": False,
            "type": "boolean",
        }
    ),
)
