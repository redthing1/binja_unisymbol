
# binja_unisymbol

binary ninja plugin + ghidra + ida scripts for easily exchanging symbols

## features

+ **Ghidra -> Binja** symbol import
+ **IDA -> Binja** symbol import
+ **Binja -> Ghidra** symbol export
+ simple unified symbol format, supporting:
    + functions
    + instruction labels
    + data labels

## usage in binja

install this into your binja plugin directory. then, use `UniSymbol > Import Symbols` and `UniSymbol > Export Symbols` to import/export symbols.

there are also several settings to set priorities for symbols for different sources. all transferred symbols have a default priority of 1, but you can for example set imported IDA symbols to have a priority of 2, which will overwrite existing symbols.

## usage in ghidra

in [ghidra/](./ghidra), there are two scripts to both import and export UniSymbol CSV data.

## usage in ida

in [ida/](./ida), there is a script to export ida's symbols as UniSymbol CSV, which can then be imported into another tool.
