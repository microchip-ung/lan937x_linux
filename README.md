BUILD INSTRUCTIONS:
===================

Build the Source
================
The buildroot source can be built for NAND flash or SD card configuration. 

	* Navigate to "lan937x_linux/src"
	* Execute "export SRC_HOME=$PWD"
	* then Navigate to "Atmel_SOC_SAMA5D3/buildroot-at91"
	* Execute following make commands based on the image.

Buildroot as a submodule:
-----------------------------------------------------
	* git submodule init
	* git submodule update

Generating NAND Flash Image
---------------------------
	* make BR2_EXTERNAL=../buildroot_external_lan937x/ atmel_sama5d3_xplained_lan937x_defconfig
	* make
	
Generating SD Card Image as out of tree Build
---------------------------------------------
SD card image can be generated using out of tree build without the need for configuration interchange
and clean build of the source.

	* mkdir ../mmc_build
	* make O=../mmc_build/ BR2_EXTERNAL=../buildroot_external_lan937x/ atmel_sama5d3_xplained_lan937x_mmc_defconfig
	* cd ../mmc_build
	* make

output/images will have the following file
==========================================

	|----------------------------------------------------------------------------------------|
	|at91bootstrap.bin	       	| Atmel SAM A5D3 Bootstrap binary -at91bootstrap3-v3.8.5 |
	|-------------------------------|--------------------------------------------------------| 
	|u-boot.bin 			| Atmel SAM A5D3 Uboot binary – linux4sam_5.3  	 	 |	
	|-------------------------------|--------------------------------------------------------|
	|zImage				| Linux image and rootfs files for Nand Flash	 	 |	
	|rootfs.tar			|							 |							
	|rootfs.ubi			|							 |							
	|rootfs.ubifs			|							 |
	|sama5d3_eds.itb		| 							 |
	|sama5d3_eds_ksz9477.dtbo	| 							 |
	|sama5d3_eds_ksz9563.dtbo	| 							 |
	|sama5d3_eds_ksz9893.dtbo	| 							 |
	|sama5d3_eds_lan9321.dtbo	| 							 |
	|sama5d3_eds_lan9370.dtbo	| 							 |
	|sama5d3_eds_lan9373_dual.dtbo	| 							 |
	|sama5d3_eds_lan9374.dtbo	| 							 |
	|-------------------------------|--------------------------------------------------------|
	|ubootEnvtFileNandFlash.bin 	| uBoot Environment configuration binary for Nand flash  |
	|-------------------------------|--------------------------------------------------------|
	|sdcard.img 			|  SD card image					 |					
	|-------------------------------|--------------------------------------------------------|

How to generate ubootEnvtFileNandFlash.bin?
and
How to program NAND flash right after "make"
-------------------------------------------
	1. Navigate to Atmel_SOC_SAMA5D3/buildroot-at91/board/atmel/sama5d3_xplained_ksz9897/post-image.sh
	2. Uncomment any one of the line based on architecture.
	   #./board/atmel/linux/flasher_x64.sh ./output/ /dev/ttyACM0 sama5d3_xplained

	   or

	   #./board/atmel/linux/flasher.sh ./output/ /dev/ttyACM0 sama5d3_xplained
	3. Execute "make"
	   It requires SAMA5D3 board to be connected to the Linux machine
	4. ubootEnvtFileNandFlash.bin in the "output/images" directory and NAND flash will be
	   programmed.


PROGRAMMING INSTRUCTIONS:
=========================

Prerequisites:
-------------
	1. Connect USB cable of SAMA5D3 Ethernet Dev board to Host (J12)
	2. Connect UART(J10) of SAMA5D3 Ethernet Dev board to Host using FTDI cable
and Connect to FTDI port from UART console (Tera Term) with baud rate (115200)
	3. Connect LAN9370 EVB to RMII Interface (J6-1,2,3,4) of SAMA5D3 Ethernet Development 
	board

	OR 

	Connect EVB-LAN9374 to RGMII interface

NAND Flash (Windows):
---------------------
	1. Navigate to SAMA5_LAN937x_vX.X.X/windows
	2. Remove Nand En Jumper(J20) in SAMA5D3 Ethernet Dev board and Power ON
	3. Put back the Nand En jumper J20 once powered ON, now you should see the message "ROMBoot" in UART Console
	4. Open cmd prompt and execute flash_board.bat, (If it fails, invoke once again)
	5. Once programming is completed press reset in SAMA5D3 board

NAND Flash (Linux):
-------------------
	1. Navigate to SAMA5_LAN937x_vX.X.X/linux
	2. Remove Nand En Jumper(J20) in SAMA5D3 Ethernet Dev board and Power ON
	3. Put back the Nand En jumper J20 once powered ON, now you should see the message "ROMBoot" in UART Console
	4. If you are using an x86 system, run following command:
	      sudo flash_board
	5. If you are using an x64 system, run following command:
	      sudo flash_board_x64
	6. Once "DONE" is displayed, press the reset button to reboot the SAMA5D3 EDS board.

SD MMC:
-------
In order to partition and copy the image to SDCard, it requires the Etcher software. Use sdcard.img file from the latest build and create image using Etcher.

SKU Selection:
--------------
SKU can be selected on uboot menu during SAMA5D3 boot-up, follow below steps to select appropriate SKU during boot.

	* During boot-up when prompting for "Hit any key to stop autoboot", press any key and stop autoboot.
	* Pass any of each command for sku selection
	  For LAN9370: "setenv boot_chip bootm 0x21000000#kernel_dtb#lan9370"
	  For LAN9374: "setenv boot_chip bootm 0x21000000#kernel_dtb#lan9374"
	  For LAN9373 Dual-t: "setenv boot_chip bootm 0x21000000#kernel_dtb#lan9373_dual" 
	  For LAN9321: "setenv boot_chip bootm 0x21000000#kernel_dtb#lan9321"
	  For KSZ9893: "setenv boot_chip bootm 0x21000000#kernel_dtb#ksz9893"
	  For KSZ9563: "setenv boot_chip bootm 0x21000000#kernel_dtb#ksz9563"
	  For KSZ9477: "setenv boot_chip bootm 0x21000000#kernel_dtb#ksz9477"
	* Enter "saveenv" command for saving updated u-boot parameters.
	* Enter "bootd" command for booting with updated configuration.
	* Instead of "setenv" you can use "editenv boot_chip" and edit the line easily.

