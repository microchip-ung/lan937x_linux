#!/usr/bin/env bash

#video mode is hard coded video=LVDS-1:800x480-16
#board name is hard coded
#apt-get install tcl-vfs
#and make sure tcl is installed; need both tcl and tcl-vfs
#ubootEnvtFileNandFlash.bin will be generated where this script is invoked


#cd buildroot_home
export O=output/images/
tclsh board/atmel/ubootEnvBinGenerate_wsl.tcl - - - sama5d3_xplained at91-sama5d3_xplained.dtb video=LVDS-1:800x480-16
mv -f ubootEnvtFileNandFlash.bin output/images/ubootEnvtFileNandFlash.bin
#Expected output in WSL
#-I- === Parsing script arguments ===
#argument 1 is -
#argument 2 is -
#argument 3 is -
#argument 4 is sama5d3_xplained
#argument 5 is at91-sama5d3_xplained.dtb
#argument 6 is video=LVDS-1:800x480-16
#-I- === Board Family is sama5d3_xplained ===
#-I- === eccType is 0xc0902405 ===
#-I- === Load the u-boot environment variables ===