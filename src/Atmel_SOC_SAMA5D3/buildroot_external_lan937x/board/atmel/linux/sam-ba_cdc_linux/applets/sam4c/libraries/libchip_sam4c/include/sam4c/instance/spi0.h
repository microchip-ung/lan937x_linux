/* ----------------------------------------------------------------------------
 *         SAM Software Package License
 * ----------------------------------------------------------------------------
 * Copyright (c) 2012, Atmel Corporation
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the disclaimer below.
 *
 * Atmel's name may not be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * DISCLAIMER: THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * ----------------------------------------------------------------------------
 */
#ifndef _SAM4C_SPI0_INSTANCE_
#define _SAM4C_SPI0_INSTANCE_

/* ========== Register definition for SPI0 peripheral ========== */
#if (defined(__ASSEMBLY__) || defined(__IAR_SYSTEMS_ASM__))
#define REG_SPI0_CR              (0x40008000U) /**< \brief (SPI0) Control Register */
#define REG_SPI0_MR              (0x40008004U) /**< \brief (SPI0) Mode Register */
#define REG_SPI0_RDR             (0x40008008U) /**< \brief (SPI0) Receive Data Register */
#define REG_SPI0_TDR             (0x4000800CU) /**< \brief (SPI0) Transmit Data Register */
#define REG_SPI0_SR              (0x40008010U) /**< \brief (SPI0) Status Register */
#define REG_SPI0_IER             (0x40008014U) /**< \brief (SPI0) Interrupt Enable Register */
#define REG_SPI0_IDR             (0x40008018U) /**< \brief (SPI0) Interrupt Disable Register */
#define REG_SPI0_IMR             (0x4000801CU) /**< \brief (SPI0) Interrupt Mask Register */
#define REG_SPI0_CSR             (0x40008030U) /**< \brief (SPI0) Chip Select Register */
#define REG_SPI0_WPMR            (0x400080E4U) /**< \brief (SPI0) Write Protection Control Register */
#define REG_SPI0_WPSR            (0x400080E8U) /**< \brief (SPI0) Write Protection Status Register */
#define REG_SPI0_RPR             (0x40008100U) /**< \brief (SPI0) Receive Pointer Register */
#define REG_SPI0_RCR             (0x40008104U) /**< \brief (SPI0) Receive Counter Register */
#define REG_SPI0_TPR             (0x40008108U) /**< \brief (SPI0) Transmit Pointer Register */
#define REG_SPI0_TCR             (0x4000810CU) /**< \brief (SPI0) Transmit Counter Register */
#define REG_SPI0_RNPR            (0x40008110U) /**< \brief (SPI0) Receive Next Pointer Register */
#define REG_SPI0_RNCR            (0x40008114U) /**< \brief (SPI0) Receive Next Counter Register */
#define REG_SPI0_TNPR            (0x40008118U) /**< \brief (SPI0) Transmit Next Pointer Register */
#define REG_SPI0_TNCR            (0x4000811CU) /**< \brief (SPI0) Transmit Next Counter Register */
#define REG_SPI0_PTCR            (0x40008120U) /**< \brief (SPI0) Transfer Control Register */
#define REG_SPI0_PTSR            (0x40008124U) /**< \brief (SPI0) Transfer Status Register */
#else
#define REG_SPI0_CR     (*(WoReg*)0x40008000U) /**< \brief (SPI0) Control Register */
#define REG_SPI0_MR     (*(RwReg*)0x40008004U) /**< \brief (SPI0) Mode Register */
#define REG_SPI0_RDR    (*(RoReg*)0x40008008U) /**< \brief (SPI0) Receive Data Register */
#define REG_SPI0_TDR    (*(WoReg*)0x4000800CU) /**< \brief (SPI0) Transmit Data Register */
#define REG_SPI0_SR     (*(RoReg*)0x40008010U) /**< \brief (SPI0) Status Register */
#define REG_SPI0_IER    (*(WoReg*)0x40008014U) /**< \brief (SPI0) Interrupt Enable Register */
#define REG_SPI0_IDR    (*(WoReg*)0x40008018U) /**< \brief (SPI0) Interrupt Disable Register */
#define REG_SPI0_IMR    (*(RoReg*)0x4000801CU) /**< \brief (SPI0) Interrupt Mask Register */
#define REG_SPI0_CSR    (*(RwReg*)0x40008030U) /**< \brief (SPI0) Chip Select Register */
#define REG_SPI0_WPMR   (*(RwReg*)0x400080E4U) /**< \brief (SPI0) Write Protection Control Register */
#define REG_SPI0_WPSR   (*(RoReg*)0x400080E8U) /**< \brief (SPI0) Write Protection Status Register */
#define REG_SPI0_RPR    (*(RwReg*)0x40008100U) /**< \brief (SPI0) Receive Pointer Register */
#define REG_SPI0_RCR    (*(RwReg*)0x40008104U) /**< \brief (SPI0) Receive Counter Register */
#define REG_SPI0_TPR    (*(RwReg*)0x40008108U) /**< \brief (SPI0) Transmit Pointer Register */
#define REG_SPI0_TCR    (*(RwReg*)0x4000810CU) /**< \brief (SPI0) Transmit Counter Register */
#define REG_SPI0_RNPR   (*(RwReg*)0x40008110U) /**< \brief (SPI0) Receive Next Pointer Register */
#define REG_SPI0_RNCR   (*(RwReg*)0x40008114U) /**< \brief (SPI0) Receive Next Counter Register */
#define REG_SPI0_TNPR   (*(RwReg*)0x40008118U) /**< \brief (SPI0) Transmit Next Pointer Register */
#define REG_SPI0_TNCR   (*(RwReg*)0x4000811CU) /**< \brief (SPI0) Transmit Next Counter Register */
#define REG_SPI0_PTCR   (*(WoReg*)0x40008120U) /**< \brief (SPI0) Transfer Control Register */
#define REG_SPI0_PTSR   (*(RoReg*)0x40008124U) /**< \brief (SPI0) Transfer Status Register */
#endif /* (defined(__ASSEMBLY__) || defined(__IAR_SYSTEMS_ASM__)) */

#endif /* _SAM4C_SPI0_INSTANCE_ */
