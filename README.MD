# Python Dissasembler

This project contains disassembler.py a script that can read a binary and it will attempt to disassemble it into Intel x86 assembly code. This does not support all instructions, but implement a subset of them.

## Prerequisite

Have a working Python 3 install in your computer. This script does not require any additional packages other than the base python packages.

## Usage 

To use the script run the following:
```
linux-machine:~/git/re_disassembler$ ./disassembler.py -i <Binary file>
```

This will output a stacktrace of the process the dissasembler did to decode the binary and at the end the complete assembly code.