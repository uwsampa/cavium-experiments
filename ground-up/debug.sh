#!/bin/bash

# Build the program (optional, via command line arg) and debug with gdb. 
# Intended for use with PCIe-attached evaluation board.

if [[ $# -eq 1 && ($1 -eq "make"  || $1 -eq "m") ]]; then
  echo "BUILDING PROGRAM..."
  make
  make_exit_code=$?
fi

if [[ $make_exit_code -eq 0 ]]; then
  oct-pci-reset
  oct-pci-load 0 ground-up
  oct-pci-bootcmd "bootoct 0 coremask=0x3 debug=1"
  mipsisa64-octeon-elf-gdb ground-up
else
  echo "BUILD FAILED!"
fi

