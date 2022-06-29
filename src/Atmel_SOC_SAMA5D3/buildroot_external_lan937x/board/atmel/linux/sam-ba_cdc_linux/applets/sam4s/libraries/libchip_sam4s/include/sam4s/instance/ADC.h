/* %ATMEL_LICENCE% */

#ifndef _SAM4S_ADC_INSTANCE_
#define _SAM4S_ADC_INSTANCE_

/* ========== Register definition for ADC peripheral ========== */
#ifdef __ASSEMBLY__
#define REG_ADC_CR               (0x40038000U) /**< \brief (ADC) Control Register */
#define REG_ADC_MR               (0x40038004U) /**< \brief (ADC) Mode Register */
#define REG_ADC_SEQR1            (0x40038008U) /**< \brief (ADC) Channel Sequence Register 1 */
#define REG_ADC_SEQR2            (0x4003800CU) /**< \brief (ADC) Channel Sequence Register 2 */
#define REG_ADC_CHER             (0x40038010U) /**< \brief (ADC) Channel Enable Register */
#define REG_ADC_CHDR             (0x40038014U) /**< \brief (ADC) Channel Disable Register */
#define REG_ADC_CHSR             (0x40038018U) /**< \brief (ADC) Channel Status Register */
#define REG_ADC_LCDR             (0x40038020U) /**< \brief (ADC) Last Converted Data Register */
#define REG_ADC_IER              (0x40038024U) /**< \brief (ADC) Interrupt Enable Register */
#define REG_ADC_IDR              (0x40038028U) /**< \brief (ADC) Interrupt Disable Register */
#define REG_ADC_IMR              (0x4003802CU) /**< \brief (ADC) Interrupt Mask Register */
#define REG_ADC_ISR              (0x40038030U) /**< \brief (ADC) Interrupt Status Register */
#define REG_ADC_OVER             (0x4003803CU) /**< \brief (ADC) Overrun Status Register */
#define REG_ADC_EMR              (0x40038040U) /**< \brief (ADC) Extended Mode Register */
#define REG_ADC_CWR              (0x40038044U) /**< \brief (ADC) Compare Window Register */
#define REG_ADC_CGR              (0x40038048U) /**< \brief (ADC) Channel Gain Register */
#define REG_ADC_COR              (0x4003804CU) /**< \brief (ADC) Channel Offset Register */
#define REG_ADC_CDR              (0x40038050U) /**< \brief (ADC) Channel Data Register */
#define REG_ADC_ACR              (0x40038094U) /**< \brief (ADC) Analog Control Register */
#define REG_ADC_WPMR             (0x400380E4U) /**< \brief (ADC) Write Protect Mode Register */
#define REG_ADC_WPSR             (0x400380E8U) /**< \brief (ADC) Write Protect Status Register */
#define REG_ADC_RPR              (0x40038100U) /**< \brief (ADC) Receive Pointer Register */
#define REG_ADC_RCR              (0x40038104U) /**< \brief (ADC) Receive Counter Register */
#define REG_ADC_TPR              (0x40038108U) /**< \brief (ADC) Transmit Pointer Register */
#define REG_ADC_TCR              (0x4003810CU) /**< \brief (ADC) Transmit Counter Register */
#define REG_ADC_RNPR             (0x40038110U) /**< \brief (ADC) Receive Next Pointer Register */
#define REG_ADC_RNCR             (0x40038114U) /**< \brief (ADC) Receive Next Counter Register */
#define REG_ADC_TNPR             (0x40038118U) /**< \brief (ADC) Transmit Next Pointer Register */
#define REG_ADC_TNCR             (0x4003811CU) /**< \brief (ADC) Transmit Next Counter Register */
#define REG_ADC_PTCR             (0x40038120U) /**< \brief (ADC) Transfer Control Register */
#define REG_ADC_PTSR             (0x40038124U) /**< \brief (ADC) Transfer Status Register */
#else
#define REG_ADC_CR      (*(WoReg*)0x40038000U) /**< \brief (ADC) Control Register */
#define REG_ADC_MR      (*(RwReg*)0x40038004U) /**< \brief (ADC) Mode Register */
#define REG_ADC_SEQR1   (*(RwReg*)0x40038008U) /**< \brief (ADC) Channel Sequence Register 1 */
#define REG_ADC_SEQR2   (*(RwReg*)0x4003800CU) /**< \brief (ADC) Channel Sequence Register 2 */
#define REG_ADC_CHER    (*(WoReg*)0x40038010U) /**< \brief (ADC) Channel Enable Register */
#define REG_ADC_CHDR    (*(WoReg*)0x40038014U) /**< \brief (ADC) Channel Disable Register */
#define REG_ADC_CHSR    (*(RoReg*)0x40038018U) /**< \brief (ADC) Channel Status Register */
#define REG_ADC_LCDR    (*(RoReg*)0x40038020U) /**< \brief (ADC) Last Converted Data Register */
#define REG_ADC_IER     (*(WoReg*)0x40038024U) /**< \brief (ADC) Interrupt Enable Register */
#define REG_ADC_IDR     (*(WoReg*)0x40038028U) /**< \brief (ADC) Interrupt Disable Register */
#define REG_ADC_IMR     (*(RoReg*)0x4003802CU) /**< \brief (ADC) Interrupt Mask Register */
#define REG_ADC_ISR     (*(RoReg*)0x40038030U) /**< \brief (ADC) Interrupt Status Register */
#define REG_ADC_OVER    (*(RoReg*)0x4003803CU) /**< \brief (ADC) Overrun Status Register */
#define REG_ADC_EMR     (*(RwReg*)0x40038040U) /**< \brief (ADC) Extended Mode Register */
#define REG_ADC_CWR     (*(RwReg*)0x40038044U) /**< \brief (ADC) Compare Window Register */
#define REG_ADC_CGR     (*(RwReg*)0x40038048U) /**< \brief (ADC) Channel Gain Register */
#define REG_ADC_COR     (*(RwReg*)0x4003804CU) /**< \brief (ADC) Channel Offset Register */
#define REG_ADC_CDR     (*(RoReg*)0x40038050U) /**< \brief (ADC) Channel Data Register */
#define REG_ADC_ACR     (*(RwReg*)0x40038094U) /**< \brief (ADC) Analog Control Register */
#define REG_ADC_WPMR    (*(RwReg*)0x400380E4U) /**< \brief (ADC) Write Protect Mode Register */
#define REG_ADC_WPSR    (*(RoReg*)0x400380E8U) /**< \brief (ADC) Write Protect Status Register */
#define REG_ADC_RPR     (*(RwReg*)0x40038100U) /**< \brief (ADC) Receive Pointer Register */
#define REG_ADC_RCR     (*(RwReg*)0x40038104U) /**< \brief (ADC) Receive Counter Register */
#define REG_ADC_TPR     (*(RwReg*)0x40038108U) /**< \brief (ADC) Transmit Pointer Register */
#define REG_ADC_TCR     (*(RwReg*)0x4003810CU) /**< \brief (ADC) Transmit Counter Register */
#define REG_ADC_RNPR    (*(RwReg*)0x40038110U) /**< \brief (ADC) Receive Next Pointer Register */
#define REG_ADC_RNCR    (*(RwReg*)0x40038114U) /**< \brief (ADC) Receive Next Counter Register */
#define REG_ADC_TNPR    (*(RwReg*)0x40038118U) /**< \brief (ADC) Transmit Next Pointer Register */
#define REG_ADC_TNCR    (*(RwReg*)0x4003811CU) /**< \brief (ADC) Transmit Next Counter Register */
#define REG_ADC_PTCR    (*(WoReg*)0x40038120U) /**< \brief (ADC) Transfer Control Register */
#define REG_ADC_PTSR    (*(RoReg*)0x40038124U) /**< \brief (ADC) Transfer Status Register */
#endif /* __ASSEMBLY__ */

#endif /* _SAM4S_ADC_INSTANCE_ */
