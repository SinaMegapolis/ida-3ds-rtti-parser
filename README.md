# ida-3ds-rtti-parser
An IDAPython Parser for Nintendo 3DS's RTTI based on ida-better-rtti-parser.

The way this parser works is by tracking down all mangled RTTI strings then tracking the actual typeinfo back through XREFs and parsing any vftable associated with each typeinfo.

NOTE: This IDAPython script has only been tested with Pokemon XY and IDA Pro 7.6 (HexRays Decompiler included). Your mileage may vary!

##How to Use

1-Load a codebase that has ARMCC based (?) RunTime TypeInfo.

2-File -> Script File

3-Navigate to the repo's folder and run rtti-parse.py

4-???

5-Profit?
