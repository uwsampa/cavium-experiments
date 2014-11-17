An extremely simple test program. To build and run on PCIe-attached board:

make
oct-pci-reset
oct-pci-load 0 simple-test
oct-pci-bootcmd "bootoct 0 coremask=0x1"

To run on more than one core, set the coremask accordingly.
