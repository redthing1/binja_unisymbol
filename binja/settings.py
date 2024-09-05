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
            "ignore": ["SettingsProjectScope", "SettingsResourceScope"],
        }
    ),
)

# bool: treat all Ghidra symbols as auto-analysis
my_settings.register_setting(
    "unisymbol.ghidra_symbols_as_auto_analysis",
    json.dumps(
        {
            "title": "Treat Ghidra Symbols as Auto-Analysis",
            "description": "Treat all imported Ghidra symbols as auto-analysis.",
            "default": False,
            "type": "boolean",
        }
    ),
)

# int: Ghidra symbol priority
my_settings.register_setting(
    "unisymbol.ghidra_symbol_priority",
    json.dumps(
        {
            "title": "Ghidra Symbol Priority",
            "description": "The priority of Ghidra symbols.",
            "default": 1,
            "type": "number",
        }
    ),
)

# bool: treat all IDA symbols as auto-analysis
my_settings.register_setting(
    "unisymbol.ida_symbols_as_auto_analysis",
    json.dumps(
        {
            "title": "Treat IDA Symbols as Auto-Analysis",
            "description": "Treat all imported IDA symbols as auto-analysis.",
            "default": False,
            "type": "boolean",
        }
    ),
)

# int: IDA symbol priority
my_settings.register_setting(
    "unisymbol.ida_symbol_priority",
    json.dumps(
        {
            "title": "IDA Symbol Priority",
            "description": "The priority of IDA symbols.",
            "default": 1,
            "type": "number",
        }
    ),
)
