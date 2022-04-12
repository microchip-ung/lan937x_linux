#!/bin/sh

#grep BR2_LINUX_KERNEL_CUSTOM_DTS_PATH $BR2_CONFIG - Parse .config file and check for path
DTB=$(grep BR2_LINUX_KERNEL_CUSTOM_DTS_PATH $BR2_CONFIG | cut -d "/" -f 1,3 --complement | cut -d "/" -f 2 | cut -d "." -f 1)

#echo $DTB

rm -f ${BINARIES_DIR}/at91-sama5d3_xplained.dtb

cp -p ${BINARIES_DIR}/$DTB.dtb ${BINARIES_DIR}/at91-sama5d3_xplained.dtb

#!/usr/bin/env bash
#This script will invoke ./board/atmel/linux/ubootenvGen.sh
#ubootEnvtFileNandFlash.bin will be generated in output/images directory
#cd buildroot_home

#For 64 bit - To Program all binaries after image generation enable following line.
./../buildroot_external_lan937x/board/atmel/linux/flasher_x64.sh ./output/ /dev/ttyACM0 sama5d3_xplained

#For 32 bit
#./board/atmel/linux/flasher.sh ./output/ /dev/ttyACM0 sama5d3_xplained

export O=output/images/

####### Not Recommended to enable following lines and test#########
#tclsh board/atmel/ubootEnvBinGenerate_wsl.tcl - - - sama5d3_xplained at91-sama5d3_xplained.dtb video=LVDS-1:800x480-16
#mv -f ubootEnvtFileNandFlash.bin output/images/ubootEnvtFileNandFlash.bin
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
