/* %ATMEL_LICENCE% */

#ifndef _SAM4S_TWI1_INSTANCE_
#define _SAM4S_TWI1_INSTANCE_

/* ========== Register definition for TWI1 peripheral ========== */
#ifdef __ASSEMBLY__
#define REG_TWI1_CR            (0x4001C000U) /**< \brief (TWI1) Control Register */
#define REG_TWI1_MMR           (0x4001C004U) /**< \brief (TWI1) Master Mode Register */
#define REG_TWI1_SMR           (0x4001C008U) /**< \brief (TWI1) Slave Mode Register */
#define REG_TWI1_IADR          (0x4001C00CU) /**< \brief (TWI1) Internal Address Register */
#define REG_TWI1_CWGR          (0x4001C010U) /**< \brief (TWI1) Clock Waveform Generator Register */
#define REG_TWI1_SR            (0x4001C020U) /**< \brief (TWI1) Status Register */
#define REG_TWI1_IER           (0x4001C024U) /**< \brief (TWI1) Interrupt Enable Register */
#define REG_TWI1_IDR           (0x4001C028U) /**< \brief (TWI1) Interrupt Disable Register */
#define REG_TWI1_IMR           (0x4001C02CU) /**< \brief (TWI1) Interrupt Mask Register */
#define REG_TWI1_RHR           (0x4001C030U) /**< \brief (TWI1) Receive Holding Register */
#define REG_TWI1_THR           (0x4001C034U) /**< \brief (TWI1) Transmit Holding Register */
#define REG_TWI1_RPR           (0x4001C100U) /**< \brief (TWI1) Receive Pointer Register */
#define REG_TWI1_RCR           (0x4001C104U) /**< \brief (TWI1) Receive Counter Register */
#define REG_TWI1_TPR           (0x4001C108U) /**< \brief (TWI1) Transmit Pointer Register */
#define REG_TWI1_TCR           (0x4001C10CU) /**< \brief (TWI1) Transmit Counter Register */
#define REG_TWI1_RNPR          (0x4001C110U) /**< \brief (TWI1) Receive Next Pointer Register */
#define REG_TWI1_RNCR          (0x4001C114U) /**< \brief (TWI1) Receive Next Counter Register */
#define REG_TWI1_TNPR          (0x4001C118U) /**< \brief (TWI1) Transmit Next Pointer Register */
#define REG_TWI1_TNCR          (0x4001C11CU) /**< \brief (TWI1) Transmit Next Counter Register */
#define REG_TWI1_PTCR          (0x4001C120U) /**< \brief (TWI1) Transfer Control Register */
#define REG_TWI1_PTSR          (0x4001C124U) /**< \brief (TWI1) Transfer Status Register */
#else
#define REG_TWI1_CR   (*(WoReg*)0x4001C000U) /**< \brief (TWI1) Control Register */
#define REG_TWI1_MMR  (*(RwReg*)0x4001C004U) /**< \brief (TWI1) Master Mode Register */
#define REG_TWI1_SMR  (*(RwReg*)0x4001C008U) /**< \brief (TWI1) Slave Mode Register */
#define REG_TWI1_IADR (*(RwReg*)0x4001C00CU) /**< \brief (TWI1) Internal Address Register */
#define REG_TWI1_CWGR (*(RwReg*)0x4001C010U) /**< \brief (TWI1) Clock Waveform Generator Register */
#define REG_TWI1_SR   (*(RoReg*)0x4001C020U) /**< \brief (TWI1) Status Register */
#define REG_TWI1_IER  (*(WoReg*)0x4001C024U) /**< \brief (TWI1) Interrupt Enable Register */
#define REG_TWI1_IDR  (*(WoReg*)0x4001C028U) /**< \brief (TWI1) Interrupt Disable Register */
#define REG_TWI1_IMR  (*(RoReg*)0x4001C02CU) /**< \brief (TWI1) Interrupt Mask Register */
#define REG_TWI1_RHR  (*(RoReg*)0x4001C030U) /**< \brief (TWI1) Receive Holding Register */
#define REG_TWI1_THR  (*(WoReg*)0x4001C034U) /**< \brief (TWI1) Transmit Holding Register */
#define REG_TWI1_RPR  (*(RwReg*)0x4001C100U) /**< \brief (TWI1) Receive Pointer Register */
#define REG_TWI1_RCR  (*(RwReg*)0x4001C104U) /**< \brief (TWI1) Receive Counter Register */
#define REG_TWI1_TPR  (*(RwReg*)0x4001C108U) /**< \brief (TWI1) Transmit Pointer Register */
#define REG_TWI1_TCR  (*(RwReg*)0x4001C10CU) /**< \brief (TWI1) Transmit Counter Register */
#define REG_TWI1_RNPR (*(RwReg*)0x4001C110U) /**< \brief (TWI1) Receive Next Pointer Register */
#define REG_TWI1_RNCR (*(RwReg*)0x4001C114U) /**< \brief (TWI1) Receive Next Counter Register */
#define REG_TWI1_TNPR (*(RwReg*)0x4001C118U) /**< \brief (TWI1) Transmit Next Pointer Register */
#define REG_TWI1_TNCR (*(RwReg*)0x4001C11CU) /**< \brief (TWI1) Transmit Next Counter Register */
#define REG_TWI1_PTCR (*(WoReg*)0x4001C120U) /**< \brief (TWI1) Transfer Control Register */
#define REG_TWI1_PTSR (*(RoReg*)0x4001C124U) /**< \brief (TWI1) Transfer Status Register */
#endif /* __ASSEMBLY__ */

#endif /* _SAM4S_TWI1_INSTANCE_ */
