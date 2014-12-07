#!/bin/bash

# Script for running traffic-gen on a PCIe-attached OCTEON board.
# Takes an optional command line argument "make" which instructs
# the script to rebuild ground-up before loading and running it
# on the board.

make_exit_code=0

if [[ $# -eq 1 && ($1 -eq "make"  || $1 -eq "m") ]]; then
  echo "BUILDING PROGRAM..."
  make
  make_exit_code=$?
fi

if [[ $make_exit_code -eq 0 ]]; then
  oct-pci-reset
  oct-pci-load 0 traffic-gen
  # use all 32 cores available
  oct-pci-bootcmd "bootoct 0 coremask=0xffffffff"
else
  echo "BUILD FAILED!"
fi
