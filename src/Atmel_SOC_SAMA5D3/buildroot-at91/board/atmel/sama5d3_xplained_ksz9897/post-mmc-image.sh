#!/bin/sh

BOARD_DIR="$(dirname $0)"
GENIMAGE_CFG="${BOARD_DIR}/genimage.cfg"
GENIMAGE_TMP="${BUILD_DIR}/genimage.tmp"

#grep BR2_LINUX_KERNEL_CUSTOM_DTS_PATH $BR2_CONFIG - Parse .config file and check for path
DTB=$(grep BR2_LINUX_KERNEL_CUSTOM_DTS_PATH $BR2_CONFIG | cut -d "/" -f 1,3 --complement | cut -d "/" -f 2 | cut -d "." -f 1)

#echo $DTB

rm -f ${BINARIES_DIR}/at91-sama5d3_xplained.dtb

cp -p ${BINARIES_DIR}/$DTB.dtb ${BINARIES_DIR}/at91-sama5d3_xplained.dtb

install -p -m 644 ${BOARD_DIR}/uboot.env ${BINARIES_DIR}/uboot.env

rm -rf "${GENIMAGE_TMP}"

genimage                               \
	--rootpath "${TARGET_DIR}"     \
	--tmppath "${GENIMAGE_TMP}"    \
	--inputpath "${BINARIES_DIR}"  \
	--outputpath "${BINARIES_DIR}" \
	--config "${GENIMAGE_CFG}"		\
	--loglevel 5
