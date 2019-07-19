# NDEF Mifare

NDEF_Mifare is a small tool to read/write NDEF data from/to a Mifare 1k/4k tag
using a librfid supported RFID reader device (e.g. openpcd or cardman 5321).

To compile this tool you first need to build [librfid](https://github.com/dpavlin/librfid). Than drop ndef_mifare.c
and the makefile contained in this archive into the utils directory of 
librfid and run: make -f makefile

Happy hacking. 

Collin <collin[at]mulliner.org>

