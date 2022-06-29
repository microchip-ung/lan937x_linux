/* ---------------------------------------------------------------------------- */ 
/*                  Atmel Microcontroller Software Support                      */
/* ---------------------------------------------------------------------------- */
/* Copyright (c) 2011, Atmel Corporation                                        */
/*                                                                              */
/* All rights reserved.                                                         */
/*                                                                              */
/* Redistribution and use in source and binary forms, with or without           */
/* modification, are permitted provided that the following condition is met:    */
/*                                                                              */
/* - Redistributions of source code must retain the above copyright notice,     */
/* this list of conditions and the disclaimer below.                            */
/*                                                                              */
/* Atmel's name may not be used to endorse or promote products derived from     */
/* this software without specific prior written permission.                     */
/*                                                                              */
/* DISCLAIMER:  THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR   */
/* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF */
/* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE   */
/* DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR ANY DIRECT, INDIRECT,      */
/* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT */
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,  */
/* OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF    */
/* LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING         */
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, */
/* EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.                           */
/* ---------------------------------------------------------------------------- */

#ifndef SAM9N12_H
#define SAM9N12_H

/** \addtogroup SAM9N12_definitions SAM9N12 definitions
  This file defines all structures and symbols for SAM9N12:
    - registers and bitfields
    - peripheral base address
    - peripheral ID
    - PIO definitions
*/
/*@{*/

#ifdef __cplusplus
 extern "C" {
#endif 

#ifndef __ASSEMBLY__
#include <stdint.h>
#ifndef __cplusplus
typedef volatile const uint32_t RoReg; /**< Read only 32-bit register (volatile const unsigned int) */
#else
typedef volatile       uint32_t RoReg; /**< Read only 32-bit register (volatile const unsigned int) */
#endif
typedef volatile       uint32_t WoReg; /**< Write only 32-bit register (volatile unsigned int) */
typedef volatile       uint32_t RwReg; /**< Read-Write 32-bit register (volatile unsigned int) */
#define CAST(type, value) ((type *)(value))
#define REG_ACCESS(type, address) (*(type*)(address)) /**< C code: Register value */
#else
#define CAST(type, value) (value) 
#define REG_ACCESS(type, address) (address) /**< Assembly code: Register address */
#endif

typedef enum IRQn
{
  FIQ_IRQn             =  0, /**<  0 SAM9N12 Advanced Interrupt Controller (FIQ) */
  SYS_IRQn             =  1, /**<  1 SAM9N12 System Controller Interrupt (SYS) */
  PIOAB_IRQn           =  2, /**<  2 SAM9N12 Parallel I/O Controller A and B (PIOAB) */
  PIOCD_IRQn           =  3, /**<  3 SAM9N12 Parallel I/O Controller C and D (PIOCD) */
  FUSE_IRQn            =  4, /**<  4 SAM9N12 FUSE Controller (FUSE) */
  USART0_IRQn          =  5, /**<  5 SAM9N12 USART 0 (USART0) */
  USART1_IRQn          =  6, /**<  6 SAM9N12 USART 1 (USART1) */
  USART2_IRQn          =  7, /**<  7 SAM9N12 USART 2 (USART2) */
  USART3_IRQn          =  8, /**<  8 SAM9N12 USART 3 (USART3) */
  TWI0_IRQn            =  9, /**<  9 SAM9N12 Two-Wire Interface 0 (TWI0) */
  TWI1_IRQn            = 10, /**< 10 SAM9N12 Two-Wire Interface 1 (TWI1) */
  HSMCI_IRQn           = 12, /**< 12 SAM9N12 High Speed Multimedia Card Interface (HSMCI) */
  SPI0_IRQn            = 13, /**< 13 SAM9N12 Serial Peripheral Interface 0 (SPI0) */
  SPI1_IRQn            = 14, /**< 14 SAM9N12 Serial Peripheral Interface 1 (SPI1) */
  UART0_IRQn           = 15, /**< 15 SAM9N12 UART 0 (UART0) */
  UART1_IRQn           = 16, /**< 16 SAM9N12 UART 1 (UART1) */
  TC01_IRQn            = 17, /**< 17 SAM9N12 Timer Counter 0 + 1 (TC01) */
  PWM_IRQn             = 18, /**< 18 SAM9N12 Pulse Width Modulation Controller (PWM) */
  ADC_IRQn             = 19, /**< 19 SAM9N12 ADC Controller (ADC) */
  DMAC_IRQn            = 20, /**< 20 SAM9N12 DMA Controller (DMAC) */
  UHP_IRQn             = 22, /**< 22 SAM9N12 USB Host (UHP) */
  UDP_IRQn             = 23, /**< 23 SAM9N12 USB Device (UDP) */
  LCDC_IRQn            = 25, /**< 25 SAM9N12 LCD Controller (LCDC) */
  SSC_IRQn             = 28, /**< 28 SAM9N12 Synchronous Serial Controller (SSC) */
  TRNG_IRQn            = 30, /**< 30 SAM9N12 True Random Number Generator (TRNG) */
  IRQ_IRQn             = 31  /**< 31 SAM9N12 Advanced Interrupt Controller (IRQ) */
} IRQn_Type;

/* ************************************************************************** */
/**  SOFTWARE PERIPHERAL API DEFINITION FOR SAM9N12 */
/* ************************************************************************** */
/** \addtogroup SAM9N12_api Peripheral Software API */
/*@{*/

/* ============================================================================= */
/**  SOFTWARE API DEFINITION FOR Advanced Interrupt Controller */
/* ============================================================================= */
/** \addtogroup SAM9N12_AIC Advanced Interrupt Controller */
/*@{*/

#ifndef __ASSEMBLY__
/** \brief Aic hardware registers */
typedef struct {
  RwReg AIC_SMR[32];   /**< \brief (Aic Offset: 0x00) Source Mode Register */
  RwReg AIC_SVR[32];   /**< \brief (Aic Offset: 0x80) Source Vector Register */
  RoReg AIC_IVR;       /**< \brief (Aic Offset: 0x100) Interrupt Vector Register */
  RoReg AIC_FVR;       /**< \brief (Aic Offset: 0x104) FIQ Interrupt Vector Register */
  RoReg AIC_ISR;       /**< \brief (Aic Offset: 0x108) Interrupt Status Register */
  RoReg AIC_IPR;       /**< \brief (Aic Offset: 0x10C) Interrupt Pending Register */
  RoReg AIC_IMR;       /**< \brief (Aic Offset: 0x110) Interrupt Mask Register */
  RoReg AIC_CISR;      /**< \brief (Aic Offset: 0x114) Core Interrupt Status Register */
  RoReg Reserved1[2];
  WoReg AIC_IECR;      /**< \brief (Aic Offset: 0x120) Interrupt Enable Command Register */
  WoReg AIC_IDCR;      /**< \brief (Aic Offset: 0x124) Interrupt Disable Command Register */
  WoReg AIC_ICCR;      /**< \brief (Aic Offset: 0x128) Interrupt Clear Command Register */
  WoReg AIC_ISCR;      /**< \brief (Aic Offset: 0x12C) Interrupt Set Command Register */
  WoReg AIC_EOICR;     /**< \brief (Aic Offset: 0x130) End of Interrupt Command Register */
  RwReg AIC_SPU;       /**< \brief (Aic Offset: 0x134) Spurious Interrupt Vector Register */
  RwReg AIC_DCR;       /**< \brief (Aic Offset: 0x138) Debug Control Register */
  RoReg Reserved2[1];
  WoReg AIC_FFER;      /**< \brief (Aic Offset: 0x140) Fast Forcing Enable Register */
  WoReg AIC_FFDR;      /**< \brief (Aic Offset: 0x144) Fast Forcing Disable Register */
  RoReg AIC_FFSR;      /**< \brief (Aic Offset: 0x148) Fast Forcing Status Register */
  RoReg Reserved3[38];
  RwReg AIC_WPMR;      /**< \brief (Aic Offset: 0x1E4) Write Protect Mode Register */
  RoReg AIC_WPSR;      /**< \brief (Aic Offset: 0x1E8) Write Protect Status Register */
} Aic;
#endif /* __ASSEMBLY__ */
/* -------- AIC_SMR[32] : (AIC Offset: 0x00) Source Mode Register -------- */
#define AIC_SMR_PRIOR_Pos 0
#define AIC_SMR_PRIOR_Msk (0x7u << AIC_SMR_PRIOR_Pos) /**< \brief (AIC_SMR[32]) Priority Level */
#define   AIC_SMR_PRIOR_LOWEST (0x0u << 0) /**< \brief (AIC_SMR[32]) Lowest priority for the corresponding interrupt */
#define   AIC_SMR_PRIOR_HIGHEST (0x7u << 0) /**< \brief (AIC_SMR[32]) Highest priority for the corresponding interrupt */
#define AIC_SMR_SRCTYPE_Pos 5
#define AIC_SMR_SRCTYPE_Msk (0x3u << AIC_SMR_SRCTYPE_Pos) /**< \brief (AIC_SMR[32]) Interrupt Source Type */
#define   AIC_SMR_SRCTYPE_INT_LEVEL_SENSITIVE (0x0u << 5) /**< \brief (AIC_SMR[32]) High level Sensitive for internal sourceLow level Sensitive for external source */
#define   AIC_SMR_SRCTYPE_INT_EDGE_TRIGGERED (0x1u << 5) /**< \brief (AIC_SMR[32]) Positive edge triggered for internal sourceNegative edge triggered for external source */
#define   AIC_SMR_SRCTYPE_EXT_HIGH_LEVEL (0x2u << 5) /**< \brief (AIC_SMR[32]) High level Sensitive for internal sourceHigh level Sensitive for external source */
#define   AIC_SMR_SRCTYPE_EXT_POSITIVE_EDGE (0x3u << 5) /**< \brief (AIC_SMR[32]) Positive edge triggered for internal sourcePositive edge triggered for external source */
/* -------- AIC_SVR[32] : (AIC Offset: 0x80) Source Vector Register -------- */
#define AIC_SVR_VECTOR_Pos 0
#define AIC_SVR_VECTOR_Msk (0xffffffffu << AIC_SVR_VECTOR_Pos) /**< \brief (AIC_SVR[32]) Source Vector */
#define AIC_SVR_VECTOR(value) ((AIC_SVR_VECTOR_Msk & ((value) << AIC_SVR_VECTOR_Pos)))
/* -------- AIC_IVR : (AIC Offset: 0x100) Interrupt Vector Register -------- */
#define AIC_IVR_IRQV_Pos 0
#define AIC_IVR_IRQV_Msk (0xffffffffu << AIC_IVR_IRQV_Pos) /**< \brief (AIC_IVR) Interrupt Vector Register */
/* -------- AIC_FVR : (AIC Offset: 0x104) FIQ Interrupt Vector Register -------- */
#define AIC_FVR_FIQV_Pos 0
#define AIC_FVR_FIQV_Msk (0xffffffffu << AIC_FVR_FIQV_Pos) /**< \brief (AIC_FVR) FIQ Vector Register */
/* -------- AIC_ISR : (AIC Offset: 0x108) Interrupt Status Register -------- */
#define AIC_ISR_IRQID_Pos 0
#define AIC_ISR_IRQID_Msk (0x1fu << AIC_ISR_IRQID_Pos) /**< \brief (AIC_ISR) Current Interrupt Identifier */
/* -------- AIC_IPR : (AIC Offset: 0x10C) Interrupt Pending Register -------- */
#define AIC_IPR_FIQ (0x1u << 0) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_SYS (0x1u << 1) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID2 (0x1u << 2) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID3 (0x1u << 3) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID4 (0x1u << 4) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID5 (0x1u << 5) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID6 (0x1u << 6) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID7 (0x1u << 7) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID8 (0x1u << 8) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID9 (0x1u << 9) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID10 (0x1u << 10) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID11 (0x1u << 11) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID12 (0x1u << 12) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID13 (0x1u << 13) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID14 (0x1u << 14) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID15 (0x1u << 15) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID16 (0x1u << 16) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID17 (0x1u << 17) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID18 (0x1u << 18) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID19 (0x1u << 19) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID20 (0x1u << 20) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID21 (0x1u << 21) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID22 (0x1u << 22) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID23 (0x1u << 23) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID24 (0x1u << 24) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID25 (0x1u << 25) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID26 (0x1u << 26) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID27 (0x1u << 27) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID28 (0x1u << 28) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID29 (0x1u << 29) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID30 (0x1u << 30) /**< \brief (AIC_IPR) Interrupt Pending */
#define AIC_IPR_PID31 (0x1u << 31) /**< \brief (AIC_IPR) Interrupt Pending */
/* -------- AIC_IMR : (AIC Offset: 0x110) Interrupt Mask Register -------- */
#define AIC_IMR_FIQ (0x1u << 0) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_SYS (0x1u << 1) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID2 (0x1u << 2) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID3 (0x1u << 3) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID4 (0x1u << 4) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID5 (0x1u << 5) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID6 (0x1u << 6) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID7 (0x1u << 7) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID8 (0x1u << 8) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID9 (0x1u << 9) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID10 (0x1u << 10) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID11 (0x1u << 11) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID12 (0x1u << 12) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID13 (0x1u << 13) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID14 (0x1u << 14) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID15 (0x1u << 15) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID16 (0x1u << 16) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID17 (0x1u << 17) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID18 (0x1u << 18) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID19 (0x1u << 19) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID20 (0x1u << 20) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID21 (0x1u << 21) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID22 (0x1u << 22) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID23 (0x1u << 23) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID24 (0x1u << 24) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID25 (0x1u << 25) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID26 (0x1u << 26) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID27 (0x1u << 27) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID28 (0x1u << 28) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID29 (0x1u << 29) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID30 (0x1u << 30) /**< \brief (AIC_IMR) Interrupt Mask */
#define AIC_IMR_PID31 (0x1u << 31) /**< \brief (AIC_IMR) Interrupt Mask */
/* -------- AIC_CISR : (AIC Offset: 0x114) Core Interrupt Status Register -------- */
#define AIC_CISR_NFIQ (0x1u << 0) /**< \brief (AIC_CISR) NFIQ Status */
#define AIC_CISR_NIRQ (0x1u << 1) /**< \brief (AIC_CISR) NIRQ Status */
/* -------- AIC_IECR : (AIC Offset: 0x120) Interrupt Enable Command Register -------- */
#define AIC_IECR_FIQ (0x1u << 0) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_SYS (0x1u << 1) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID2 (0x1u << 2) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID3 (0x1u << 3) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID4 (0x1u << 4) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID5 (0x1u << 5) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID6 (0x1u << 6) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID7 (0x1u << 7) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID8 (0x1u << 8) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID9 (0x1u << 9) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID10 (0x1u << 10) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID11 (0x1u << 11) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID12 (0x1u << 12) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID13 (0x1u << 13) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID14 (0x1u << 14) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID15 (0x1u << 15) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID16 (0x1u << 16) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID17 (0x1u << 17) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID18 (0x1u << 18) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID19 (0x1u << 19) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID20 (0x1u << 20) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID21 (0x1u << 21) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID22 (0x1u << 22) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID23 (0x1u << 23) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID24 (0x1u << 24) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID25 (0x1u << 25) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID26 (0x1u << 26) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID27 (0x1u << 27) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID28 (0x1u << 28) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID29 (0x1u << 29) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID30 (0x1u << 30) /**< \brief (AIC_IECR) Interrupt Enable */
#define AIC_IECR_PID31 (0x1u << 31) /**< \brief (AIC_IECR) Interrupt Enable */
/* -------- AIC_IDCR : (AIC Offset: 0x124) Interrupt Disable Command Register -------- */
#define AIC_IDCR_FIQ (0x1u << 0) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_SYS (0x1u << 1) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID2 (0x1u << 2) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID3 (0x1u << 3) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID4 (0x1u << 4) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID5 (0x1u << 5) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID6 (0x1u << 6) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID7 (0x1u << 7) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID8 (0x1u << 8) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID9 (0x1u << 9) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID10 (0x1u << 10) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID11 (0x1u << 11) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID12 (0x1u << 12) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID13 (0x1u << 13) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID14 (0x1u << 14) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID15 (0x1u << 15) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID16 (0x1u << 16) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID17 (0x1u << 17) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID18 (0x1u << 18) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID19 (0x1u << 19) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID20 (0x1u << 20) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID21 (0x1u << 21) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID22 (0x1u << 22) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID23 (0x1u << 23) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID24 (0x1u << 24) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID25 (0x1u << 25) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID26 (0x1u << 26) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID27 (0x1u << 27) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID28 (0x1u << 28) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID29 (0x1u << 29) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID30 (0x1u << 30) /**< \brief (AIC_IDCR) Interrupt Disable */
#define AIC_IDCR_PID31 (0x1u << 31) /**< \brief (AIC_IDCR) Interrupt Disable */
/* -------- AIC_ICCR : (AIC Offset: 0x128) Interrupt Clear Command Register -------- */
#define AIC_ICCR_FIQ (0x1u << 0) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_SYS (0x1u << 1) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID2 (0x1u << 2) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID3 (0x1u << 3) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID4 (0x1u << 4) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID5 (0x1u << 5) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID6 (0x1u << 6) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID7 (0x1u << 7) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID8 (0x1u << 8) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID9 (0x1u << 9) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID10 (0x1u << 10) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID11 (0x1u << 11) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID12 (0x1u << 12) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID13 (0x1u << 13) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID14 (0x1u << 14) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID15 (0x1u << 15) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID16 (0x1u << 16) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID17 (0x1u << 17) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID18 (0x1u << 18) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID19 (0x1u << 19) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID20 (0x1u << 20) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID21 (0x1u << 21) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID22 (0x1u << 22) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID23 (0x1u << 23) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID24 (0x1u << 24) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID25 (0x1u << 25) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID26 (0x1u << 26) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID27 (0x1u << 27) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID28 (0x1u << 28) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID29 (0x1u << 29) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID30 (0x1u << 30) /**< \brief (AIC_ICCR) Interrupt Clear */
#define AIC_ICCR_PID31 (0x1u << 31) /**< \brief (AIC_ICCR) Interrupt Clear */
/* -------- AIC_ISCR : (AIC Offset: 0x12C) Interrupt Set Command Register -------- */
#define AIC_ISCR_FIQ (0x1u << 0) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_SYS (0x1u << 1) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID2 (0x1u << 2) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID3 (0x1u << 3) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID4 (0x1u << 4) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID5 (0x1u << 5) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID6 (0x1u << 6) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID7 (0x1u << 7) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID8 (0x1u << 8) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID9 (0x1u << 9) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID10 (0x1u << 10) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID11 (0x1u << 11) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID12 (0x1u << 12) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID13 (0x1u << 13) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID14 (0x1u << 14) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID15 (0x1u << 15) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID16 (0x1u << 16) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID17 (0x1u << 17) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID18 (0x1u << 18) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID19 (0x1u << 19) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID20 (0x1u << 20) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID21 (0x1u << 21) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID22 (0x1u << 22) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID23 (0x1u << 23) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID24 (0x1u << 24) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID25 (0x1u << 25) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID26 (0x1u << 26) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID27 (0x1u << 27) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID28 (0x1u << 28) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID29 (0x1u << 29) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID30 (0x1u << 30) /**< \brief (AIC_ISCR) Interrupt Set */
#define AIC_ISCR_PID31 (0x1u << 31) /**< \brief (AIC_ISCR) Interrupt Set */
/* -------- AIC_SPU : (AIC Offset: 0x134) Spurious Interrupt Vector Register -------- */
#define AIC_SPU_SIVR_Pos 0
#define AIC_SPU_SIVR_Msk (0xffffffffu << AIC_SPU_SIVR_Pos) /**< \brief (AIC_SPU) Spurious Interrupt Vector Register */
#define AIC_SPU_SIVR(value) ((AIC_SPU_SIVR_Msk & ((value) << AIC_SPU_SIVR_Pos)))
/* -------- AIC_DCR : (AIC Offset: 0x138) Debug Control Register -------- */
#define AIC_DCR_PROT (0x1u << 0) /**< \brief (AIC_DCR) Protection Mode */
#define AIC_DCR_GMSK (0x1u << 1) /**< \brief (AIC_DCR) General Mask */
/* -------- AIC_FFER : (AIC Offset: 0x140) Fast Forcing Enable Register -------- */
#define AIC_FFER_SYS (0x1u << 1) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID2 (0x1u << 2) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID3 (0x1u << 3) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID4 (0x1u << 4) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID5 (0x1u << 5) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID6 (0x1u << 6) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID7 (0x1u << 7) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID8 (0x1u << 8) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID9 (0x1u << 9) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID10 (0x1u << 10) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID11 (0x1u << 11) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID12 (0x1u << 12) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID13 (0x1u << 13) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID14 (0x1u << 14) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID15 (0x1u << 15) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID16 (0x1u << 16) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID17 (0x1u << 17) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID18 (0x1u << 18) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID19 (0x1u << 19) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID20 (0x1u << 20) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID21 (0x1u << 21) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID22 (0x1u << 22) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID23 (0x1u << 23) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID24 (0x1u << 24) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID25 (0x1u << 25) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID26 (0x1u << 26) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID27 (0x1u << 27) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID28 (0x1u << 28) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID29 (0x1u << 29) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID30 (0x1u << 30) /**< \brief (AIC_FFER) Fast Forcing Enable */
#define AIC_FFER_PID31 (0x1u << 31) /**< \brief (AIC_FFER) Fast Forcing Enable */
/* -------- AIC_FFDR : (AIC Offset: 0x144) Fast Forcing Disable Register -------- */
#define AIC_FFDR_SYS (0x1u << 1) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID2 (0x1u << 2) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID3 (0x1u << 3) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID4 (0x1u << 4) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID5 (0x1u << 5) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID6 (0x1u << 6) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID7 (0x1u << 7) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID8 (0x1u << 8) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID9 (0x1u << 9) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID10 (0x1u << 10) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID11 (0x1u << 11) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID12 (0x1u << 12) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID13 (0x1u << 13) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID14 (0x1u << 14) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID15 (0x1u << 15) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID16 (0x1u << 16) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID17 (0x1u << 17) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID18 (0x1u << 18) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID19 (0x1u << 19) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID20 (0x1u << 20) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID21 (0x1u << 21) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID22 (0x1u << 22) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID23 (0x1u << 23) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID24 (0x1u << 24) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID25 (0x1u << 25) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID26 (0x1u << 26) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID27 (0x1u << 27) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID28 (0x1u << 28) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID29 (0x1u << 29) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID30 (0x1u << 30) /**< \brief (AIC_FFDR) Fast Forcing Disable */
#define AIC_FFDR_PID31 (0x1u << 31) /**< \brief (AIC_FFDR) Fast Forcing Disable */
/* -------- AIC_FFSR : (AIC Offset: 0x148) Fast Forcing Status Register -------- */
#define AIC_FFSR_SYS (0x1u << 1) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID2 (0x1u << 2) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID3 (0x1u << 3) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID4 (0x1u << 4) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID5 (0x1u << 5) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID6 (0x1u << 6) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID7 (0x1u << 7) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID8 (0x1u << 8) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID9 (0x1u << 9) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID10 (0x1u << 10) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID11 (0x1u << 11) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID12 (0x1u << 12) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID13 (0x1u << 13) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID14 (0x1u << 14) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID15 (0x1u << 15) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID16 (0x1u << 16) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID17 (0x1u << 17) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID18 (0x1u << 18) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID19 (0x1u << 19) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID20 (0x1u << 20) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID21 (0x1u << 21) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID22 (0x1u << 22) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID23 (0x1u << 23) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID24 (0x1u << 24) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID25 (0x1u << 25) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID26 (0x1u << 26) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID27 (0x1u << 27) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID28 (0x1u << 28) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID29 (0x1u << 29) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID30 (0x1u << 30) /**< \brief (AIC_FFSR) Fast Forcing Status */
#define AIC_FFSR_PID31 (0x1u << 31) /**< \brief (AIC_FFSR) Fast Forcing Status */
/* -------- AIC_WPMR : (AIC Offset: 0x1E4) Write Protect Mode Register -------- */
#define AIC_WPMR_WPEN (0x1u << 0) /**< \brief (AIC_WPMR) Write Protect Enable */
#define AIC_WPMR_WPKEY_Pos 8
#define AIC_WPMR_WPKEY_Msk (0xffffffu << AIC_WPMR_WPKEY_Pos) /**< \brief (AIC_WPMR) Write Protect KEY */
#define AIC_WPMR_WPKEY(value) ((AIC_WPMR_WPKEY_Msk & ((value) << AIC_WPMR_WPKEY_Pos)))
/* -------- AIC_WPSR : (AIC Offset: 0x1E8) Write Protect Status Register -------- */
#define AIC_WPSR_WPVS (0x1u << 0) /**< \brief (AIC_WPSR) Write Protect Violation Status */
#define AIC_WPSR_WPVSRC_Pos 8
#define AIC_WPSR_WPVSRC_Msk (0xffffu << AIC_WPSR_WPVSRC_Pos) /**< \brief (AIC_WPSR) Write Protect Violation Source */

/*@}*/

/* ============================================================================= */
/**  SOFTWARE API DEFINITION FOR Debug Unit */
/* ============================================================================= */
/** \addtogroup SAM9N12_DBGU Debug Unit */
/*@{*/

#ifndef __ASSEMBLY__
/** \brief Dbgu hardware registers */
typedef struct {
  WoReg DBGU_CR;      /**< \brief (Dbgu Offset: 0x0000) Control Register */
  RwReg DBGU_MR;      /**< \brief (Dbgu Offset: 0x0004) Mode Register */
  WoReg DBGU_IER;     /**< \brief (Dbgu Offset: 0x0008) Interrupt Enable Register */
  WoReg DBGU_IDR;     /**< \brief (Dbgu Offset: 0x000C) Interrupt Disable Register */
  RoReg DBGU_IMR;     /**< \brief (Dbgu Offset: 0x0010) Interrupt Mask Register */
  RoReg DBGU_SR;      /**< \brief (Dbgu Offset: 0x0014) Status Register */
  RoReg DBGU_RHR;     /**< \brief (Dbgu Offset: 0x0018) Receive Holding Register */
  WoReg DBGU_THR;     /**< \brief (Dbgu Offset: 0x001C) Transmit Holding Register */
  RwReg DBGU_BRGR;    /**< \brief (Dbgu Offset: 0x0020) Baud Rate Generator Register */
  RoReg Reserved1[7];
  RoReg DBGU_CIDR;    /**< \brief (Dbgu Offset: 0x0040) Chip ID Register */
  RoReg DBGU_EXID;    /**< \brief (Dbgu Offset: 0x0044) Chip ID Extension Register */
  RwReg DBGU_FNR;     /**< \brief (Dbgu Offset: 0x0048) Force NTRST Register */
} Dbgu;
#endif /* __ASSEMBLY__ */
/* -------- DBGU_CR : (DBGU Offset: 0x0000) Control Register -------- */
#define DBGU_CR_RSTRX (0x1u << 2) /**< \brief (DBGU_CR) Reset Receiver */
#define DBGU_CR_RSTTX (0x1u << 3) /**< \brief (DBGU_CR) Reset Transmitter */
#define DBGU_CR_RXEN (0x1u << 4) /**< \brief (DBGU_CR) Receiver Enable */
#define DBGU_CR_RXDIS (0x1u << 5) /**< \brief (DBGU_CR) Receiver Disable */
#define DBGU_CR_TXEN (0x1u << 6) /**< \brief (DBGU_CR) Transmitter Enable */
#define DBGU_CR_TXDIS (0x1u << 7) /**< \brief (DBGU_CR) Transmitter Disable */
#define DBGU_CR_RSTSTA (0x1u << 8) /**< \brief (DBGU_CR) Reset Status Bits */
/* -------- DBGU_MR : (DBGU Offset: 0x0004) Mode Register -------- */
#define DBGU_MR_PAR_Pos 9
#define DBGU_MR_PAR_Msk (0x7u << DBGU_MR_PAR_Pos) /**< \brief (DBGU_MR) Parity Type */
#define   DBGU_MR_PAR_EVEN (0x0u << 9) /**< \brief (DBGU_MR) Even Parity */
#define   DBGU_MR_PAR_ODD (0x1u << 9) /**< \brief (DBGU_MR) Odd Parity */
#define   DBGU_MR_PAR_SPACE (0x2u << 9) /**< \brief (DBGU_MR) Space: Parity forced to 0 */
#define   DBGU_MR_PAR_MARK (0x3u << 9) /**< \brief (DBGU_MR) Mark: Parity forced to 1 */
#define   DBGU_MR_PAR_NONE (0x4u << 9) /**< \brief (DBGU_MR) No Parity */
#define DBGU_MR_CHMODE_Pos 14
#define DBGU_MR_CHMODE_Msk (0x3u << DBGU_MR_CHMODE_Pos) /**< \brief (DBGU_MR) Channel Mode */
#define   DBGU_MR_CHMODE_NORM (0x0u << 14) /**< \brief (DBGU_MR) Normal Mode */
#define   DBGU_MR_CHMODE_AUTO (0x1u << 14) /**< \brief (DBGU_MR) Automatic Echo */
#define   DBGU_MR_CHMODE_LOCLOOP (0x2u << 14) /**< \brief (DBGU_MR) Local Loopback */
#define   DBGU_MR_CHMODE_REMLOOP (0x3u << 14) /**< \brief (DBGU_MR) Remote Loopback */
/* -------- DBGU_IER : (DBGU Offset: 0x0008) Interrupt Enable Register -------- */
#define DBGU_IER_RXRDY (0x1u << 0) /**< \brief (DBGU_IER) Enable RXRDY Interrupt */
#define DBGU_IER_TXRDY (0x1u << 1) /**< \brief (DBGU_IER) Enable TXRDY Interrupt */
#define DBGU_IER_OVRE (0x1u << 5) /**< \brief (DBGU_IER) Enable Overrun Error Interrupt */
#define DBGU_IER_FRAME (0x1u << 6) /**< \brief (DBGU_IER) Enable Framing Error Interrupt */
#define DBGU_IER_PARE (0x1u << 7) /**< \brief (DBGU_IER) Enable Parity Error Interrupt */
#define DBGU_IER_TXEMPTY (0x1u << 9) /**< \brief (DBGU_IER) Enable TXEMPTY Interrupt */
#define DBGU_IER_COMMTX (0x1u << 30) /**< \brief (DBGU_IER) Enable COMMTX (from ARM) Interrupt */
#define DBGU_IER_COMMRX (0x1u << 31) /**< \brief (DBGU_IER) Enable COMMRX (from ARM) Interrupt */
/* -------- DBGU_IDR : (DBGU Offset: 0x000C) Interrupt Disable Register -------- */
#define DBGU_IDR_RXRDY (0x1u << 0) /**< \brief (DBGU_IDR) Disable RXRDY Interrupt */
#define DBGU_IDR_TXRDY (0x1u << 1) /**< \brief (DBGU_IDR) Disable TXRDY Interrupt */
#define DBGU_IDR_OVRE (0x1u << 5) /**< \brief (DBGU_IDR) Disable Overrun Error Interrupt */
#define DBGU_IDR_FRAME (0x1u << 6) /**< \brief (DBGU_IDR) Disable Framing Error Interrupt */
#define DBGU_IDR_PARE (0x1u << 7) /**< \brief (DBGU_IDR) Disable Parity Error Interrupt */
#define DBGU_IDR_TXEMPTY (0x1u << 9) /**< \brief (DBGU_IDR) Disable TXEMPTY Interrupt */
#define DBGU_IDR_COMMTX (0x1u << 30) /**< \brief (DBGU_IDR) Disable COMMTX (from ARM) Interrupt */
#define DBGU_IDR_COMMRX (0x1u << 31) /**< \brief (DBGU_IDR) Disable COMMRX (from ARM) Interrupt */
/* -------- DBGU_IMR : (DBGU Offset: 0x0010) Interrupt Mask Register -------- */
#define DBGU_IMR_RXRDY (0x1u << 0) /**< \brief (DBGU_IMR) Mask RXRDY Interrupt */
#define DBGU_IMR_TXRDY (0x1u << 1) /**< \brief (DBGU_IMR) Disable TXRDY Interrupt */
#define DBGU_IMR_OVRE (0x1u << 5) /**< \brief (DBGU_IMR) Mask Overrun Error Interrupt */
#define DBGU_IMR_FRAME (0x1u << 6) /**< \brief (DBGU_IMR) Mask Framing Error Interrupt */
#define DBGU_IMR_PARE (0x1u << 7) /**< \brief (DBGU_IMR) Mask Parity Error Interrupt */
#define DBGU_IMR_TXEMPTY (0x1u << 9) /**< \brief (DBGU_IMR) Mask TXEMPTY Interrupt */
#define DBGU_IMR_COMMTX (0x1u << 30) /**< \brief (DBGU_IMR) Mask COMMTX Interrupt */
#define DBGU_IMR_COMMRX (0x1u << 31) /**< \brief (DBGU_IMR) Mask COMMRX Interrupt */
/* -------- DBGU_SR : (DBGU Offset: 0x0014) Status Register -------- */
#define DBGU_SR_RXRDY (0x1u << 0) /**< \brief (DBGU_SR) Receiver Ready */
#define DBGU_SR_TXRDY (0x1u << 1) /**< \brief (DBGU_SR) Transmitter Ready */
#define DBGU_SR_OVRE (0x1u << 5) /**< \brief (DBGU_SR) Overrun Error */
#define DBGU_SR_FRAME (0x1u << 6) /**< \brief (DBGU_SR) Framing Error */
#define DBGU_SR_PARE (0x1u << 7) /**< \brief (DBGU_SR) Parity Error */
#define DBGU_SR_TXEMPTY (0x1u << 9) /**< \brief (DBGU_SR) Transmitter Empty */
#define DBGU_SR_COMMTX (0x1u << 30) /**< \brief (DBGU_SR) Debug Communication Channel Write Status */
#define DBGU_SR_COMMRX (0x1u << 31) /**< \brief (DBGU_SR) Debug Communication Channel Read Status */
/* -------- DBGU_RHR : (DBGU Offset: 0x0018) Receive Holding Register -------- */
#define DBGU_RHR_RXCHR_Pos 0
#define DBGU_RHR_RXCHR_Msk (0xffu << DBGU_RHR_RXCHR_Pos) /**< \brief (DBGU_RHR) Received Character */
/* -------- DBGU_THR : (DBGU Offset: 0x001C) Transmit Holding Register -------- */
#define DBGU_THR_TXCHR_Pos 0
#define DBGU_THR_TXCHR_Msk (0xffu << DBGU_THR_TXCHR_Pos) /**< \brief (DBGU_THR) Character to be Transmitted */
#define DBGU_THR_TXCHR(value) ((DBGU_THR_TXCHR_Msk & ((value) << DBGU_THR_TXCHR_Pos)))
/* -------- DBGU_BRGR : (DBGU Offset: 0x0020) Baud Rate Generator Register -------- */
#define DBGU_BRGR_CD_Pos 0
#define DBGU_BRGR_CD_Msk (0xffffu << DBGU_BRGR_CD_Pos) /**< \brief (DBGU_BRGR) Clock Divisor */
#define   DBGU_BRGR_CD_DISABLED (0x0u << 0) /**< \brief (DBGU_BRGR) DBGU Disabled */
#define   DBGU_BRGR_CD_MCK (0x1u << 0) /**< \brief (DBGU_BRGR) MCK */
/* -------- DBGU_CIDR : (DBGU Offset: 0x0040) Chip ID Register -------- */
#define DBGU_CIDR_VERSION_Pos 0
#define DBGU_CIDR_VERSION_Msk (0x1fu << DBGU_CIDR_VERSION_Pos) /**< \brief (DBGU_CIDR) Version of the Device */
#define DBGU_CIDR_EPROC_Pos 5
#define DBGU_CIDR_EPROC_Msk (0x7u << DBGU_CIDR_EPROC_Pos) /**< \brief (DBGU_CIDR) Embedded Processor */
#define   DBGU_CIDR_EPROC_ARM946ES (0x1u << 5) /**< \brief (DBGU_CIDR) ARM946ES */
#define   DBGU_CIDR_EPROC_ARM7TDMI (0x2u << 5) /**< \brief (DBGU_CIDR) ARM7TDMI */
#define   DBGU_CIDR_EPROC_CM3 (0x3u << 5) /**< \brief (DBGU_CIDR) Cortex-M3 */
#define   DBGU_CIDR_EPROC_ARM920T (0x4u << 5) /**< \brief (DBGU_CIDR) ARM920T */
#define   DBGU_CIDR_EPROC_ARM926EJS (0x5u << 5) /**< \brief (DBGU_CIDR) ARM926EJS */
#define   DBGU_CIDR_EPROC_CA5 (0x6u << 5) /**< \brief (DBGU_CIDR) Cortex-A5 */
#define DBGU_CIDR_NVPSIZ_Pos 8
#define DBGU_CIDR_NVPSIZ_Msk (0xfu << DBGU_CIDR_NVPSIZ_Pos) /**< \brief (DBGU_CIDR) Nonvolatile Program Memory Size */
#define   DBGU_CIDR_NVPSIZ_NONE (0x0u << 8) /**< \brief (DBGU_CIDR) None */
#define   DBGU_CIDR_NVPSIZ_8K (0x1u << 8) /**< \brief (DBGU_CIDR) 8K bytes */
#define   DBGU_CIDR_NVPSIZ_16K (0x2u << 8) /**< \brief (DBGU_CIDR) 16K bytes */
#define   DBGU_CIDR_NVPSIZ_32K (0x3u << 8) /**< \brief (DBGU_CIDR) 32K bytes */
#define   DBGU_CIDR_NVPSIZ_64K (0x5u << 8) /**< \brief (DBGU_CIDR) 64K bytes */
#define   DBGU_CIDR_NVPSIZ_128K (0x7u << 8) /**< \brief (DBGU_CIDR) 128K bytes */
#define   DBGU_CIDR_NVPSIZ_256K (0x9u << 8) /**< \brief (DBGU_CIDR) 256K bytes */
#define   DBGU_CIDR_NVPSIZ_512K (0xAu << 8) /**< \brief (DBGU_CIDR) 512K bytes */
#define   DBGU_CIDR_NVPSIZ_1024K (0xCu << 8) /**< \brief (DBGU_CIDR) 1024K bytes */
#define   DBGU_CIDR_NVPSIZ_2048K (0xEu << 8) /**< \brief (DBGU_CIDR) 2048K bytes */
#define DBGU_CIDR_NVPSIZ2_Pos 12
#define DBGU_CIDR_NVPSIZ2_Msk (0xfu << DBGU_CIDR_NVPSIZ2_Pos) /**< \brief (DBGU_CIDR)  */
#define   DBGU_CIDR_NVPSIZ2_NONE (0x0u << 12) /**< \brief (DBGU_CIDR) None */
#define   DBGU_CIDR_NVPSIZ2_8K (0x1u << 12) /**< \brief (DBGU_CIDR) 8K bytes */
#define   DBGU_CIDR_NVPSIZ2_16K (0x2u << 12) /**< \brief (DBGU_CIDR) 16K bytes */
#define   DBGU_CIDR_NVPSIZ2_32K (0x3u << 12) /**< \brief (DBGU_CIDR) 32K bytes */
#define   DBGU_CIDR_NVPSIZ2_64K (0x5u << 12) /**< \brief (DBGU_CIDR) 64K bytes */
#define   DBGU_CIDR_NVPSIZ2_128K (0x7u << 12) /**< \brief (DBGU_CIDR) 128K bytes */
#define   DBGU_CIDR_NVPSIZ2_256K (0x9u << 12) /**< \brief (DBGU_CIDR) 256K bytes */
#define   DBGU_CIDR_NVPSIZ2_512K (0xAu << 12) /**< \brief (DBGU_CIDR) 512K bytes */
#define   DBGU_CIDR_NVPSIZ2_1024K (0xCu << 12) /**< \brief (DBGU_CIDR) 1024K bytes */
#define   DBGU_CIDR_NVPSIZ2_2048K (0xEu << 12) /**< \brief (DBGU_CIDR) 2048K bytes */
#define DBGU_CIDR_SRAMSIZ_Pos 16
#define DBGU_CIDR_SRAMSIZ_Msk (0xfu << DBGU_CIDR_SRAMSIZ_Pos) /**< \brief (DBGU_CIDR) Internal SRAM Size */
#define   DBGU_CIDR_SRAMSIZ_1K (0x1u << 16) /**< \brief (DBGU_CIDR) 1K bytes */
#define   DBGU_CIDR_SRAMSIZ_2K (0x2u << 16) /**< \brief (DBGU_CIDR) 2K bytes */
#define   DBGU_CIDR_SRAMSIZ_6K (0x3u << 16) /**< \brief (DBGU_CIDR) 6K bytes */
#define   DBGU_CIDR_SRAMSIZ_112K (0x4u << 16) /**< \brief (DBGU_CIDR) 112K bytes */
#define   DBGU_CIDR_SRAMSIZ_4K (0x5u << 16) /**< \brief (DBGU_CIDR) 4K bytes */
#define   DBGU_CIDR_SRAMSIZ_80K (0x6u << 16) /**< \brief (DBGU_CIDR) 80K bytes */
#define   DBGU_CIDR_SRAMSIZ_160K (0x7u << 16) /**< \brief (DBGU_CIDR) 160K bytes */
#define   DBGU_CIDR_SRAMSIZ_8K (0x8u << 16) /**< \brief (DBGU_CIDR) 8K bytes */
#define   DBGU_CIDR_SRAMSIZ_16K (0x9u << 16) /**< \brief (DBGU_CIDR) 16K bytes */
#define   DBGU_CIDR_SRAMSIZ_32K (0xAu << 16) /**< \brief (DBGU_CIDR) 32K bytes */
#define   DBGU_CIDR_SRAMSIZ_64K (0xBu << 16) /**< \brief (DBGU_CIDR) 64K bytes */
#define   DBGU_CIDR_SRAMSIZ_128K (0xCu << 16) /**< \brief (DBGU_CIDR) 128K bytes */
#define   DBGU_CIDR_SRAMSIZ_256K (0xDu << 16) /**< \brief (DBGU_CIDR) 256K bytes */
#define   DBGU_CIDR_SRAMSIZ_96K (0xEu << 16) /**< \brief (DBGU_CIDR) 96K bytes */
#define   DBGU_CIDR_SRAMSIZ_512K (0xFu << 16) /**< \brief (DBGU_CIDR) 512K bytes */
#define DBGU_CIDR_ARCH_Pos 20
#define DBGU_CIDR_ARCH_Msk (0xffu << DBGU_CIDR_ARCH_Pos) /**< \brief (DBGU_CIDR) Architecture Identifier */
#define   DBGU_CIDR_ARCH_AT91SAM9xx (0x19u << 20) /**< \brief (DBGU_CIDR) AT91SAM9xx Series */
#define   DBGU_CIDR_ARCH_AT91SAM9XExx (0x29u << 20) /**< \brief (DBGU_CIDR) AT91SAM9XExx Series */
#define   DBGU_CIDR_ARCH_AT91x34 (0x34u << 20) /**< \brief (DBGU_CIDR) AT91x34 Series */
#define   DBGU_CIDR_ARCH_CAP7 (0x37u << 20) /**< \brief (DBGU_CIDR) CAP7 Series */
#define   DBGU_CIDR_ARCH_CAP9 (0x39u << 20) /**< \brief (DBGU_CIDR) CAP9 Series */
#define   DBGU_CIDR_ARCH_CAP11 (0x3Bu << 20) /**< \brief (DBGU_CIDR) CAP11 Series */
#define   DBGU_CIDR_ARCH_AT91x40 (0x40u << 20) /**< \brief (DBGU_CIDR) AT91x40 Series */
#define   DBGU_CIDR_ARCH_AT91x42 (0x42u << 20) /**< \brief (DBGU_CIDR) AT91x42 Series */
#define   DBGU_CIDR_ARCH_AT91x55 (0x55u << 20) /**< \brief (DBGU_CIDR) AT91x55 Series */
#define   DBGU_CIDR_ARCH_AT91SAM7Axx (0x60u << 20) /**< \brief (DBGU_CIDR) AT91SAM7Axx Series */
#define   DBGU_CIDR_ARCH_AT91SAM7AQxx (0x61u << 20) /**< \brief (DBGU_CIDR) AT91SAM7AQxx Series */
#define   DBGU_CIDR_ARCH_AT91x63 (0x63u << 20) /**< \brief (DBGU_CIDR) AT91x63 Series */
#define   DBGU_CIDR_ARCH_AT91SAM7Sxx (0x70u << 20) /**< \brief (DBGU_CIDR) AT91SAM7Sxx Series */
#define   DBGU_CIDR_ARCH_AT91SAM7XCxx (0x71u << 20) /**< \brief (DBGU_CIDR) AT91SAM7XCxx Series */
#define   DBGU_CIDR_ARCH_AT91SAM7SExx (0x72u << 20) /**< \brief (DBGU_CIDR) AT91SAM7SExx Series */
#define   DBGU_CIDR_ARCH_AT91SAM7Lxx (0x73u << 20) /**< \brief (DBGU_CIDR) AT91SAM7Lxx Series */
#define   DBGU_CIDR_ARCH_AT91SAM7Xxx (0x75u << 20) /**< \brief (DBGU_CIDR) AT91SAM7Xxx Series */
#define   DBGU_CIDR_ARCH_AT91SAM7SLxx (0x76u << 20) /**< \brief (DBGU_CIDR) AT91SAM7SLxx Series */
#define   DBGU_CIDR_ARCH_ATSAM3UxC (0x80u << 20) /**< \brief (DBGU_CIDR) ATSAM3UxC Series (100-pin version) */
#define   DBGU_CIDR_ARCH_ATSAM3UxE (0x81u << 20) /**< \brief (DBGU_CIDR) ATSAM3UxE Series (144-pin version) */
#define   DBGU_CIDR_ARCH_ATSAM3AxC (0x83u << 20) /**< \brief (DBGU_CIDR) ATSAM3AxC Series (100-pin version) */
#define   DBGU_CIDR_ARCH_ATSAM3XxC (0x84u << 20) /**< \brief (DBGU_CIDR) ATSAM3XxC Series (100-pin version) */
#define   DBGU_CIDR_ARCH_ATSAM3XxE (0x85u << 20) /**< \brief (DBGU_CIDR) ATSAM3XxE Series (144-pin version) */
#define   DBGU_CIDR_ARCH_ATSAM3XxG (0x86u << 20) /**< \brief (DBGU_CIDR) ATSAM3XxG Series (208/217-pin version) */
#define   DBGU_CIDR_ARCH_ATSAM3SxA (0x88u << 20) /**< \brief (DBGU_CIDR) ATSAM3SxA Series (48-pin version) */
#define   DBGU_CIDR_ARCH_ATSAM3SxB (0x89u << 20) /**< \brief (DBGU_CIDR) ATSAM3SxB Series (64-pin version) */
#define   DBGU_CIDR_ARCH_ATSAM3SxC (0x8Au << 20) /**< \brief (DBGU_CIDR) ATSAM3SxC Series (100-pin version) */
#define   DBGU_CIDR_ARCH_AT91x92 (0x92u << 20) /**< \brief (DBGU_CIDR) AT91x92 Series */
#define   DBGU_CIDR_ARCH_ATSAM3NxA (0x93u << 20) /**< \brief (DBGU_CIDR) ATSAM3NxA Series (48-pin version) */
#define   DBGU_CIDR_ARCH_ATSAM3NxB (0x94u << 20) /**< \brief (DBGU_CIDR) ATSAM3NxB Series (64-pin version) */
#define   DBGU_CIDR_ARCH_ATSAM3NxC (0x95u << 20) /**< \brief (DBGU_CIDR) ATSAM3NxC Series (100-pin version) */
#define   DBGU_CIDR_ARCH_ATSAM3SDxA (0x98u << 20) /**< \brief (DBGU_CIDR) ATSAM3SDxA Series (48-pin version) */
#define   DBGU_CIDR_ARCH_ATSAM3SDxB (0x99u << 20) /**< \brief (DBGU_CIDR) ATSAM3SDxB Series (64-pin version) */
#define   DBGU_CIDR_ARCH_ATSAM3SDxC (0x9Au << 20) /**< \brief (DBGU_CIDR) ATSAM3SDxC Series (100-pin version) */
#define   DBGU_CIDR_ARCH_AT75Cxx (0xF0u << 20) /**< \brief (DBGU_CIDR) AT75Cxx Series */
#define DBGU_CIDR_NVPTYP_Pos 28
#define DBGU_CIDR_NVPTYP_Msk (0x7u << DBGU_CIDR_NVPTYP_Pos) /**< \brief (DBGU_CIDR) Nonvolatile Program Memory Type */
#define   DBGU_CIDR_NVPTYP_ROM (0x0u << 28) /**< \brief (DBGU_CIDR) ROM */
#define   DBGU_CIDR_NVPTYP_ROMLESS (0x1u << 28) /**< \brief (DBGU_CIDR) ROMless or on-chip Flash */
#define   DBGU_CIDR_NVPTYP_FLASH (0x2u << 28) /**< \brief (DBGU_CIDR) Embedded Flash Memory */
#define   DBGU_CIDR_NVPTYP_ROM_FLASH (0x3u << 28) /**< \brief (DBGU_CIDR) ROM and Embedded Flash MemoryNVPSIZ is ROM size      NVPSIZ2 is Flash size */
#define   DBGU_CIDR_NVPTYP_SRAM (0x4u << 28) /**< \brief (DBGU_CIDR) SRAM emulating ROM */
#define DBGU_CIDR_EXT (0x1u << 31) /**< \brief (DBGU_CIDR) Extension Flag */
/* -------- DBGU_EXID : (DBGU Offset: 0x0044) Chip ID Extension Register -------- */
#define DBGU_EXID_EXID_Pos 0
#define DBGU_EXID_EXID_Msk (0xffffffffu << DBGU_EXID_EXID_Pos) /**< \brief (DBGU_EXID) Chip ID Extension */
/* -------- DBGU_FNR : (DBGU Offset: 0x0048) Force NTRST Register -------- */
#define DBGU_FNR_FNTRST (0x1u << 0) /**< \brief (DBGU_FNR) Force NTRST */

/*@}*/

/* ============================================================================= */
/**  SOFTWARE API DEFINITION FOR DDR_SDR SDRAM Controller */
/* ============================================================================= */
/** \addtogroup SAM9N12_DDRSDRC DDR_SDR SDRAM Controller */
/*@{*/

#ifndef __ASSEMBLY__
/** \brief Ddrsdrc hardware registers */
typedef struct {
  RwReg DDRSDRC_MR;    /**< \brief (Ddrsdrc Offset: 0x00) DDRSDRC Mode Register */
  RwReg DDRSDRC_RTR;   /**< \brief (Ddrsdrc Offset: 0x04) DDRSDRC Refresh Timer Register */
  RwReg DDRSDRC_CR;    /**< \brief (Ddrsdrc Offset: 0x08) DDRSDRC Configuration Register */
  RwReg DDRSDRC_TPR0;  /**< \brief (Ddrsdrc Offset: 0x0C) DDRSDRC Timing Parameter 0 Register */
  RwReg DDRSDRC_TPR1;  /**< \brief (Ddrsdrc Offset: 0x10) DDRSDRC Timing Parameter 1 Register */
  RwReg DDRSDRC_TPR2;  /**< \brief (Ddrsdrc Offset: 0x14) DDRSDRC Timing Parameter 2 Register */
  RoReg Reserved1[1];
  RwReg DDRSDRC_LPR;   /**< \brief (Ddrsdrc Offset: 0x1C) DDRSDRC Low-power Register */
  RwReg DDRSDRC_MD;    /**< \brief (Ddrsdrc Offset: 0x20) DDRSDRC Memory Device Register */
  RoReg DDRSDRC_DLL;   /**< \brief (Ddrsdrc Offset: 0x24) DDRSDRC DLL Information Register */
  RoReg Reserved2[1];
  RwReg DDRSDRC_HS;    /**< \brief (Ddrsdrc Offset: 0x2C) DDRSDRC High Speed Register */
  RoReg Reserved3[45];
  RwReg DDRSDRC_WPMR;  /**< \brief (Ddrsdrc Offset: 0xE4) DDRSDRC Write Protect Mode Register */
  RoReg DDRSDRC_WPSR;  /**< \brief (Ddrsdrc Offset: 0xE8) DDRSDRC Write Protect Status Register */
} Ddrsdrc;
#endif /* __ASSEMBLY__ */
/* -------- DDRSDRC_MR : (DDRSDRC Offset: 0x00) DDRSDRC Mode Register -------- */
#define DDRSDRC_MR_MODE_Pos 0
#define DDRSDRC_MR_MODE_Msk (0x7u << DDRSDRC_MR_MODE_Pos) /**< \brief (DDRSDRC_MR) DDRSDRC Command Mode */
#define DDRSDRC_MR_MODE(value) ((DDRSDRC_MR_MODE_Msk & ((value) << DDRSDRC_MR_MODE_Pos)))
/* -------- DDRSDRC_RTR : (DDRSDRC Offset: 0x04) DDRSDRC Refresh Timer Register -------- */
#define DDRSDRC_RTR_COUNT_Pos 0
#define DDRSDRC_RTR_COUNT_Msk (0xfffu << DDRSDRC_RTR_COUNT_Pos) /**< \brief (DDRSDRC_RTR) DDRSDRC Refresh Timer Count */
#define DDRSDRC_RTR_COUNT(value) ((DDRSDRC_RTR_COUNT_Msk & ((value) << DDRSDRC_RTR_COUNT_Pos)))
/* -------- DDRSDRC_CR : (DDRSDRC Offset: 0x08) DDRSDRC Configuration Register -------- */
#define DDRSDRC_CR_NC_Pos 0
#define DDRSDRC_CR_NC_Msk (0x3u << DDRSDRC_CR_NC_Pos) /**< \brief (DDRSDRC_CR) Number of Column Bits */
#define DDRSDRC_CR_NC(value) ((DDRSDRC_CR_NC_Msk & ((value) << DDRSDRC_CR_NC_Pos)))
#define DDRSDRC_CR_NR_Pos 2
#define DDRSDRC_CR_NR_Msk (0x3u << DDRSDRC_CR_NR_Pos) /**< \brief (DDRSDRC_CR) Number of Row Bits */
#define DDRSDRC_CR_NR(value) ((DDRSDRC_CR_NR_Msk & ((value) << DDRSDRC_CR_NR_Pos)))
#define DDRSDRC_CR_CAS_Pos 4
#define DDRSDRC_CR_CAS_Msk (0x7u << DDRSDRC_CR_CAS_Pos) /**< \brief (DDRSDRC_CR) CAS Latency */
#define DDRSDRC_CR_CAS(value) ((DDRSDRC_CR_CAS_Msk & ((value) << DDRSDRC_CR_CAS_Pos)))
#define DDRSDRC_CR_DLL (0x1u << 7) /**< \brief (DDRSDRC_CR) Reset DLL */
#define DDRSDRC_CR_DIC (0x1u << 8) /**< \brief (DDRSDRC_CR) Output Driver Impedance Control */
#define DDRSDRC_CR_DS (0x1u << 8) /**< \brief (DDRSDRC_CR) Output Driver Impedance Control */
#define DDRSDRC_CR_DIS_DLL (0x1u << 9) /**< \brief (DDRSDRC_CR) Disable DLL */
#define DDRSDRC_CR_OCD_Pos 12
#define DDRSDRC_CR_OCD_Msk (0x7u << DDRSDRC_CR_OCD_Pos) /**< \brief (DDRSDRC_CR) Off-chip Driver */
#define DDRSDRC_CR_OCD(value) ((DDRSDRC_CR_OCD_Msk & ((value) << DDRSDRC_CR_OCD_Pos)))
#define DDRSDRC_CR_EBISHARE (0x1u << 16) /**< \brief (DDRSDRC_CR) External Bus Interface is Shared */
#define DDRSDRC_CR_ACTBST (0x1u << 18) /**< \brief (DDRSDRC_CR) ACTIVE Bank X to Burst Stop Read Access Bank Y */
#define DDRSDRC_CR_NB (0x1u << 20) /**< \brief (DDRSDRC_CR) Number of Banks */
#define DDRSDRC_CR_DECOD (0x1u << 22) /**< \brief (DDRSDRC_CR) Type of Decoding */
/* -------- DDRSDRC_TPR0 : (DDRSDRC Offset: 0x0C) DDRSDRC Timing Parameter 0 Register -------- */
#define DDRSDRC_TPR0_TRAS_Pos 0
#define DDRSDRC_TPR0_TRAS_Msk (0xfu << DDRSDRC_TPR0_TRAS_Pos) /**< \brief (DDRSDRC_TPR0) Active to Precharge Delay */
#define DDRSDRC_TPR0_TRAS(value) ((DDRSDRC_TPR0_TRAS_Msk & ((value) << DDRSDRC_TPR0_TRAS_Pos)))
#define DDRSDRC_TPR0_TRCD_Pos 4
#define DDRSDRC_TPR0_TRCD_Msk (0xfu << DDRSDRC_TPR0_TRCD_Pos) /**< \brief (DDRSDRC_TPR0) Row to Column Delay */
#define DDRSDRC_TPR0_TRCD(value) ((DDRSDRC_TPR0_TRCD_Msk & ((value) << DDRSDRC_TPR0_TRCD_Pos)))
#define DDRSDRC_TPR0_TWR_Pos 8
#define DDRSDRC_TPR0_TWR_Msk (0xfu << DDRSDRC_TPR0_TWR_Pos) /**< \brief (DDRSDRC_TPR0) Write Recovery Delay */
#define DDRSDRC_TPR0_TWR(value) ((DDRSDRC_TPR0_TWR_Msk & ((value) << DDRSDRC_TPR0_TWR_Pos)))
#define DDRSDRC_TPR0_TRC_Pos 12
#define DDRSDRC_TPR0_TRC_Msk (0xfu << DDRSDRC_TPR0_TRC_Pos) /**< \brief (DDRSDRC_TPR0) Row Cycle Delay */
#define DDRSDRC_TPR0_TRC(value) ((DDRSDRC_TPR0_TRC_Msk & ((value) << DDRSDRC_TPR0_TRC_Pos)))
#define DDRSDRC_TPR0_TRP_Pos 16
#define DDRSDRC_TPR0_TRP_Msk (0xfu << DDRSDRC_TPR0_TRP_Pos) /**< \brief (DDRSDRC_TPR0) Row Precharge Delay */
#define DDRSDRC_TPR0_TRP(value) ((DDRSDRC_TPR0_TRP_Msk & ((value) << DDRSDRC_TPR0_TRP_Pos)))
#define DDRSDRC_TPR0_TRRD_Pos 20
#define DDRSDRC_TPR0_TRRD_Msk (0xfu << DDRSDRC_TPR0_TRRD_Pos) /**< \brief (DDRSDRC_TPR0) Active bankA to Active bankB */
#define DDRSDRC_TPR0_TRRD(value) ((DDRSDRC_TPR0_TRRD_Msk & ((value) << DDRSDRC_TPR0_TRRD_Pos)))
#define DDRSDRC_TPR0_TWTR_Pos 24
#define DDRSDRC_TPR0_TWTR_Msk (0x7u << DDRSDRC_TPR0_TWTR_Pos) /**< \brief (DDRSDRC_TPR0) Internal Write to Read Delay */
#define DDRSDRC_TPR0_TWTR(value) ((DDRSDRC_TPR0_TWTR_Msk & ((value) << DDRSDRC_TPR0_TWTR_Pos)))
#define DDRSDRC_TPR0_REDUCE_WRRD (0x1u << 27) /**< \brief (DDRSDRC_TPR0) Reduce Write to Read Delay */
#define DDRSDRC_TPR0_TMRD_Pos 28
#define DDRSDRC_TPR0_TMRD_Msk (0xfu << DDRSDRC_TPR0_TMRD_Pos) /**< \brief (DDRSDRC_TPR0) Load Mode Register Command to Active or Refresh Command */
#define DDRSDRC_TPR0_TMRD(value) ((DDRSDRC_TPR0_TMRD_Msk & ((value) << DDRSDRC_TPR0_TMRD_Pos)))
/* -------- DDRSDRC_TPR1 : (DDRSDRC Offset: 0x10) DDRSDRC Timing Parameter 1 Register -------- */
#define DDRSDRC_TPR1_TRFC_Pos 0
#define DDRSDRC_TPR1_TRFC_Msk (0x1fu << DDRSDRC_TPR1_TRFC_Pos) /**< \brief (DDRSDRC_TPR1) Row Cycle Delay */
#define DDRSDRC_TPR1_TRFC(value) ((DDRSDRC_TPR1_TRFC_Msk & ((value) << DDRSDRC_TPR1_TRFC_Pos)))
#define DDRSDRC_TPR1_TXSNR_Pos 8
#define DDRSDRC_TPR1_TXSNR_Msk (0xffu << DDRSDRC_TPR1_TXSNR_Pos) /**< \brief (DDRSDRC_TPR1) Exit Self Refresh Delay to Non-read Command */
#define DDRSDRC_TPR1_TXSNR(value) ((DDRSDRC_TPR1_TXSNR_Msk & ((value) << DDRSDRC_TPR1_TXSNR_Pos)))
#define DDRSDRC_TPR1_TXSRD_Pos 16
#define DDRSDRC_TPR1_TXSRD_Msk (0xffu << DDRSDRC_TPR1_TXSRD_Pos) /**< \brief (DDRSDRC_TPR1) ExiT Self Refresh Delay to Read Command */
#define DDRSDRC_TPR1_TXSRD(value) ((DDRSDRC_TPR1_TXSRD_Msk & ((value) << DDRSDRC_TPR1_TXSRD_Pos)))
#define DDRSDRC_TPR1_TXP_Pos 24
#define DDRSDRC_TPR1_TXP_Msk (0xfu << DDRSDRC_TPR1_TXP_Pos) /**< \brief (DDRSDRC_TPR1) Exit Power-down Delay to First Command */
#define DDRSDRC_TPR1_TXP(value) ((DDRSDRC_TPR1_TXP_Msk & ((value) << DDRSDRC_TPR1_TXP_Pos)))
/* -------- DDRSDRC_TPR2 : (DDRSDRC Offset: 0x14) DDRSDRC Timing Parameter 2 Register -------- */
#define DDRSDRC_TPR2_TXARD_Pos 0
#define DDRSDRC_TPR2_TXARD_Msk (0xfu << DDRSDRC_TPR2_TXARD_Pos) /**< \brief (DDRSDRC_TPR2) Exit Active Power Down Delay to Read Command in Mode "Fast Exit". */
#define DDRSDRC_TPR2_TXARD(value) ((DDRSDRC_TPR2_TXARD_Msk & ((value) << DDRSDRC_TPR2_TXARD_Pos)))
#define DDRSDRC_TPR2_TXARDS_Pos 4
#define DDRSDRC_TPR2_TXARDS_Msk (0xfu << DDRSDRC_TPR2_TXARDS_Pos) /**< \brief (DDRSDRC_TPR2) Exit Active Power Down Delay to Read Command in Mode "Slow Exit". */
#define DDRSDRC_TPR2_TXARDS(value) ((DDRSDRC_TPR2_TXARDS_Msk & ((value) << DDRSDRC_TPR2_TXARDS_Pos)))
#define DDRSDRC_TPR2_TRPA_Pos 8
#define DDRSDRC_TPR2_TRPA_Msk (0xfu << DDRSDRC_TPR2_TRPA_Pos) /**< \brief (DDRSDRC_TPR2) Row Precharge All Delay */
#define DDRSDRC_TPR2_TRPA(value) ((DDRSDRC_TPR2_TRPA_Msk & ((value) << DDRSDRC_TPR2_TRPA_Pos)))
#define DDRSDRC_TPR2_TRTP_Pos 12
#define DDRSDRC_TPR2_TRTP_Msk (0x7u << DDRSDRC_TPR2_TRTP_Pos) /**< \brief (DDRSDRC_TPR2) Read to Precharge */
#define DDRSDRC_TPR2_TRTP(value) ((DDRSDRC_TPR2_TRTP_Msk & ((value) << DDRSDRC_TPR2_TRTP_Pos)))
#define DDRSDRC_TPR2_TFAW_Pos 16
#define DDRSDRC_TPR2_TFAW_Msk (0xfu << DDRSDRC_TPR2_TFAW_Pos) /**< \brief (DDRSDRC_TPR2) Four Active window */
#define DDRSDRC_TPR2_TFAW(value) ((DDRSDRC_TPR2_TFAW_Msk & ((value) << DDRSDRC_TPR2_TFAW_Pos)))
/* -------- DDRSDRC_LPR : (DDRSDRC Offset: 0x1C) DDRSDRC Low-power Register -------- */
#define DDRSDRC_LPR_LPCB_Pos 0
#define DDRSDRC_LPR_LPCB_Msk (0x3u << DDRSDRC_LPR_LPCB_Pos) /**< \brief (DDRSDRC_LPR) Low-power Command Bit */
#define DDRSDRC_LPR_LPCB(value) ((DDRSDRC_LPR_LPCB_Msk & ((value) << DDRSDRC_LPR_LPCB_Pos)))
#define DDRSDRC_LPR_CLK_FR (0x1u << 2) /**< \brief (DDRSDRC_LPR) Clock Frozen Command Bit */
#define DDRSDRC_LPR_PASR_Pos 4
#define DDRSDRC_LPR_PASR_Msk (0x7u << DDRSDRC_LPR_PASR_Pos) /**< \brief (DDRSDRC_LPR) Partial Array Self Refresh */
#define DDRSDRC_LPR_PASR(value) ((DDRSDRC_LPR_PASR_Msk & ((value) << DDRSDRC_LPR_PASR_Pos)))
#define DDRSDRC_LPR_DS_Pos 8
#define DDRSDRC_LPR_DS_Msk (0x7u << DDRSDRC_LPR_DS_Pos) /**< \brief (DDRSDRC_LPR) Drive Strength */
#define DDRSDRC_LPR_DS(value) ((DDRSDRC_LPR_DS_Msk & ((value) << DDRSDRC_LPR_DS_Pos)))
#define DDRSDRC_LPR_TIMEOUT_Pos 12
#define DDRSDRC_LPR_TIMEOUT_Msk (0x3u << DDRSDRC_LPR_TIMEOUT_Pos) /**< \brief (DDRSDRC_LPR) Low Power Mode */
#define DDRSDRC_LPR_TIMEOUT(value) ((DDRSDRC_LPR_TIMEOUT_Msk & ((value) << DDRSDRC_LPR_TIMEOUT_Pos)))
#define DDRSDRC_LPR_APDE (0x1u << 16) /**< \brief (DDRSDRC_LPR) Active Power Down Exit Time */
#define DDRSDRC_LPR_UPD_MR_Pos 20
#define DDRSDRC_LPR_UPD_MR_Msk (0x3u << DDRSDRC_LPR_UPD_MR_Pos) /**< \brief (DDRSDRC_LPR) Update Load Mode Register and Extended Mode Register */
#define DDRSDRC_LPR_UPD_MR(value) ((DDRSDRC_LPR_UPD_MR_Msk & ((value) << DDRSDRC_LPR_UPD_MR_Pos)))
/* -------- DDRSDRC_MD : (DDRSDRC Offset: 0x20) DDRSDRC Memory Device Register -------- */
#define DDRSDRC_MD_MD_Pos 0
#define DDRSDRC_MD_MD_Msk (0x7u << DDRSDRC_MD_MD_Pos) /**< \brief (DDRSDRC_MD) Memory Device */
#define DDRSDRC_MD_MD(value) ((DDRSDRC_MD_MD_Msk & ((value) << DDRSDRC_MD_MD_Pos)))
#define DDRSDRC_MD_DBW (0x1u << 4) /**< \brief (DDRSDRC_MD) Data Bus Width */
/* -------- DDRSDRC_DLL : (DDRSDRC Offset: 0x24) DDRSDRC DLL Information Register -------- */
#define DDRSDRC_DLL_MDINC (0x1u << 0) /**< \brief (DDRSDRC_DLL) DLL Master Delay Increment */
#define DDRSDRC_DLL_MDDEC (0x1u << 1) /**< \brief (DDRSDRC_DLL) DLL Master Delay Decrement */
#define DDRSDRC_DLL_MDOVF (0x1u << 2) /**< \brief (DDRSDRC_DLL) DLL Master Delay Overflow Flag */
#define DDRSDRC_DLL_MDVAL_Pos 8
#define DDRSDRC_DLL_MDVAL_Msk (0xffu << DDRSDRC_DLL_MDVAL_Pos) /**< \brief (DDRSDRC_DLL) DLL Master Delay Value */
/* -------- DDRSDRC_HS : (DDRSDRC Offset: 0x2C) DDRSDRC High Speed Register -------- */
#define DDRSDRC_HS_DIS_ANTICIP_READ (0x1u << 2) /**< \brief (DDRSDRC_HS) Anticip Read Access */
/* -------- DDRSDRC_WPMR : (DDRSDRC Offset: 0xE4) DDRSDRC Write Protect Mode Register -------- */
#define DDRSDRC_WPMR_WPEN (0x1u << 0) /**< \brief (DDRSDRC_WPMR) Write Protect Enable */
#define DDRSDRC_WPMR_WPKEY_Pos 8
#define DDRSDRC_WPMR_WPKEY_Msk (0xffffffu << DDRSDRC_WPMR_WPKEY_Pos) /**< \brief (DDRSDRC_WPMR) Write Protect KEY */
#define DDRSDRC_WPMR_WPKEY(value) ((DDRSDRC_WPMR_WPKEY_Msk & ((value) << DDRSDRC_WPMR_WPKEY_Pos)))
/* -------- DDRSDRC_WPSR : (DDRSDRC Offset: 0xE8) DDRSDRC Write Protect Status Register -------- */
#define DDRSDRC_WPSR_WPVS (0x1u << 0) /**< \brief (DDRSDRC_WPSR) Write Protect Violation Status */
#define DDRSDRC_WPSR_WPVSRC_Pos 8
#define DDRSDRC_WPSR_WPVSRC_Msk (0xffffu << DDRSDRC_WPSR_WPVSRC_Pos) /**< \brief (DDRSDRC_WPSR) Write Protect Violation Source */

/*@}*/

/* ============================================================================= */
/**  SOFTWARE API DEFINITION FOR DMA Controller */
/* ============================================================================= */
/** \addtogroup SAM9N12_DMAC DMA Controller */
/*@{*/

#ifndef __ASSEMBLY__
/** \brief DmacCh_num hardware registers */
typedef struct {
  RwReg       DMAC_SADDR;     /**< \brief (DmacCh_num Offset: 0x0) DMAC Channel Source Address Register */
  RwReg       DMAC_DADDR;     /**< \brief (DmacCh_num Offset: 0x4) DMAC Channel Destination Address Register */
  RwReg       DMAC_DSCR;      /**< \brief (DmacCh_num Offset: 0x8) DMAC Channel Descriptor Address Register */
  RwReg       DMAC_CTRLA;     /**< \brief (DmacCh_num Offset: 0xC) DMAC Channel Control A Register */
  RwReg       DMAC_CTRLB;     /**< \brief (DmacCh_num Offset: 0x10) DMAC Channel Control B Register */
  RwReg       DMAC_CFG;       /**< \brief (DmacCh_num Offset: 0x14) DMAC Channel Configuration Register */
  RwReg       DMAC_SPIP;      /**< \brief (DmacCh_num Offset: 0x18) DMAC Channel Source Picture-in-Picture Configuration Register */
  RwReg       DMAC_DPIP;      /**< \brief (DmacCh_num Offset: 0x1C) DMAC Channel Destination Picture-in-Picture Configuration Register */
  RoReg       Reserved1[2];
} DmacCh_num;
/** \brief Dmac hardware registers */
#define DMACCH_NUM_NUMBER 8
typedef struct {
  RwReg       DMAC_GCFG;      /**< \brief (Dmac Offset: 0x000) DMAC Global Configuration Register */
  RwReg       DMAC_EN;        /**< \brief (Dmac Offset: 0x004) DMAC Enable Register */
  RwReg       DMAC_SREQ;      /**< \brief (Dmac Offset: 0x008) DMAC Software Single Request Register */
  RwReg       DMAC_CREQ;      /**< \brief (Dmac Offset: 0x00C) DMAC Software Chunk Transfer Request Register */
  RwReg       DMAC_LAST;      /**< \brief (Dmac Offset: 0x010) DMAC Software Last Transfer Flag Register */
  RoReg       Reserved1[1];
  WoReg       DMAC_EBCIER;    /**< \brief (Dmac Offset: 0x018) DMAC Error, Chained Buffer Transfer Completed Interrupt and Buffer Transfer Completed Interrupt Enable register. */
  WoReg       DMAC_EBCIDR;    /**< \brief (Dmac Offset: 0x01C) DMAC Error, Chained Buffer Transfer Completed Interrupt and Buffer Transfer Completed Interrupt Disable register. */
  RoReg       DMAC_EBCIMR;    /**< \brief (Dmac Offset: 0x020) DMAC Error, Chained Buffer Transfer Completed Interrupt and Buffer transfer completed Mask Register. */
  RoReg       DMAC_EBCISR;    /**< \brief (Dmac Offset: 0x024) DMAC Error, Chained Buffer Transfer Completed Interrupt and Buffer transfer completed Status Register. */
  WoReg       DMAC_CHER;      /**< \brief (Dmac Offset: 0x028) DMAC Channel Handler Enable Register */
  WoReg       DMAC_CHDR;      /**< \brief (Dmac Offset: 0x02C) DMAC Channel Handler Disable Register */
  RoReg       DMAC_CHSR;      /**< \brief (Dmac Offset: 0x030) DMAC Channel Handler Status Register */
  RoReg       Reserved2[2];
  DmacCh_num  DMAC_CH_NUM[DMACCH_NUM_NUMBER]; /**< \brief (Dmac Offset: 0x3C) ch_num = 0 .. 7 */
  RoReg       Reserved3[26];
  RwReg       DMAC_WPMR;      /**< \brief (Dmac Offset: 0x1E4) DMAC Write Protect Mode Register */
  RoReg       DMAC_WPSR;      /**< \brief (Dmac Offset: 0x1E8) DMAC Write Protect Status Register */
} Dmac;
#endif /* __ASSEMBLY__ */
/* -------- DMAC_GCFG : (DMAC Offset: 0x000) DMAC Global Configuration Register -------- */
#define DMAC_GCFG_ARB_CFG (0x1u << 4) /**< \brief (DMAC_GCFG) Arbiter Configuration */
#define   DMAC_GCFG_ARB_CFG_FIXED (0x0u << 4) /**< \brief (DMAC_GCFG) Fixed priority arbiter. */
#define   DMAC_GCFG_ARB_CFG_ROUND_ROBIN (0x1u << 4) /**< \brief (DMAC_GCFG) Modified round robin arbiter. */
#define DMAC_GCFG_DICEN (0x1u << 8) /**< \brief (DMAC_GCFG) Descriptor Integrity Check */
/* -------- DMAC_EN : (DMAC Offset: 0x004) DMAC Enable Register -------- */
#define DMAC_EN_ENABLE (0x1u << 0) /**< \brief (DMAC_EN)  */
/* -------- DMAC_SREQ : (DMAC Offset: 0x008) DMAC Software Single Request Register -------- */
#define DMAC_SREQ_SSREQ0 (0x1u << 0) /**< \brief (DMAC_SREQ) Source Request */
#define DMAC_SREQ_DSREQ0 (0x1u << 1) /**< \brief (DMAC_SREQ) Destination Request */
#define DMAC_SREQ_SSREQ1 (0x1u << 2) /**< \brief (DMAC_SREQ) Source Request */
#define DMAC_SREQ_DSREQ1 (0x1u << 3) /**< \brief (DMAC_SREQ) Destination Request */
#define DMAC_SREQ_SSREQ2 (0x1u << 4) /**< \brief (DMAC_SREQ) Source Request */
#define DMAC_SREQ_DSREQ2 (0x1u << 5) /**< \brief (DMAC_SREQ) Destination Request */
#define DMAC_SREQ_SSREQ3 (0x1u << 6) /**< \brief (DMAC_SREQ) Source Request */
#define DMAC_SREQ_DSREQ3 (0x1u << 7) /**< \brief (DMAC_SREQ) Destination Request */
#define DMAC_SREQ_SSREQ4 (0x1u << 8) /**< \brief (DMAC_SREQ) Source Request */
#define DMAC_SREQ_DSREQ4 (0x1u << 9) /**< \brief (DMAC_SREQ) Destination Request */
#define DMAC_SREQ_SSREQ5 (0x1u << 10) /**< \brief (DMAC_SREQ) Source Request */
#define DMAC_SREQ_DSREQ5 (0x1u << 11) /**< \brief (DMAC_SREQ) Destination Request */
#define DMAC_SREQ_SSREQ6 (0x1u << 12) /**< \brief (DMAC_SREQ) Source Request */
#define DMAC_SREQ_DSREQ6 (0x1u << 13) /**< \brief (DMAC_SREQ) Destination Request */
#define DMAC_SREQ_SSREQ7 (0x1u << 14) /**< \brief (DMAC_SREQ) Source Request */
#define DMAC_SREQ_DSREQ7 (0x1u << 15) /**< \brief (DMAC_SREQ) Destination Request */
/* -------- DMAC_CREQ : (DMAC Offset: 0x00C) DMAC Software Chunk Transfer Request Register -------- */
#define DMAC_CREQ_SCREQ0 (0x1u << 0) /**< \brief (DMAC_CREQ) Source Chunk Request */
#define DMAC_CREQ_DCREQ0 (0x1u << 1) /**< \brief (DMAC_CREQ) Destination Chunk Request */
#define DMAC_CREQ_SCREQ1 (0x1u << 2) /**< \brief (DMAC_CREQ) Source Chunk Request */
#define DMAC_CREQ_DCREQ1 (0x1u << 3) /**< \brief (DMAC_CREQ) Destination Chunk Request */
#define DMAC_CREQ_SCREQ2 (0x1u << 4) /**< \brief (DMAC_CREQ) Source Chunk Request */
#define DMAC_CREQ_DCREQ2 (0x1u << 5) /**< \brief (DMAC_CREQ) Destination Chunk Request */
#define DMAC_CREQ_SCREQ3 (0x1u << 6) /**< \brief (DMAC_CREQ) Source Chunk Request */
#define DMAC_CREQ_DCREQ3 (0x1u << 7) /**< \brief (DMAC_CREQ) Destination Chunk Request */
#define DMAC_CREQ_SCREQ4 (0x1u << 8) /**< \brief (DMAC_CREQ) Source Chunk Request */
#define DMAC_CREQ_DCREQ4 (0x1u << 9) /**< \brief (DMAC_CREQ) Destination Chunk Request */
#define DMAC_CREQ_SCREQ5 (0x1u << 10) /**< \brief (DMAC_CREQ) Source Chunk Request */
#define DMAC_CREQ_DCREQ5 (0x1u << 11) /**< \brief (DMAC_CREQ) Destination Chunk Request */
#define DMAC_CREQ_SCREQ6 (0x1u << 12) /**< \brief (DMAC_CREQ) Source Chunk Request */
#define DMAC_CREQ_DCREQ6 (0x1u << 13) /**< \brief (DMAC_CREQ) Destination Chunk Request */
#define DMAC_CREQ_SCREQ7 (0x1u << 14) /**< \brief (DMAC_CREQ) Source Chunk Request */
#define DMAC_CREQ_DCREQ7 (0x1u << 15) /**< \brief (DMAC_CREQ) Destination Chunk Request */
/* -------- DMAC_LAST : (DMAC Offset: 0x010) DMAC Software Last Transfer Flag Register -------- */
#define DMAC_LAST_SLAST0 (0x1u << 0) /**< \brief (DMAC_LAST) Source Last */
#define DMAC_LAST_DLAST0 (0x1u << 1) /**< \brief (DMAC_LAST) Destination Last */
#define DMAC_LAST_SLAST1 (0x1u << 2) /**< \brief (DMAC_LAST) Source Last */
#define DMAC_LAST_DLAST1 (0x1u << 3) /**< \brief (DMAC_LAST) Destination Last */
#define DMAC_LAST_SLAST2 (0x1u << 4) /**< \brief (DMAC_LAST) Source Last */
#define DMAC_LAST_DLAST2 (0x1u << 5) /**< \brief (DMAC_LAST) Destination Last */
#define DMAC_LAST_SLAST3 (0x1u << 6) /**< \brief (DMAC_LAST) Source Last */
#define DMAC_LAST_DLAST3 (0x1u << 7) /**< \brief (DMAC_LAST) Destination Last */
#define DMAC_LAST_SLAST4 (0x1u << 8) /**< \brief (DMAC_LAST) Source Last */
#define DMAC_LAST_DLAST4 (0x1u << 9) /**< \brief (DMAC_LAST) Destination Last */
#define DMAC_LAST_SLAST5 (0x1u << 10) /**< \brief (DMAC_LAST) Source Last */
#define DMAC_LAST_DLAST5 (0x1u << 11) /**< \brief (DMAC_LAST) Destination Last */
#define DMAC_LAST_SLAST6 (0x1u << 12) /**< \brief (DMAC_LAST) Source Last */
#define DMAC_LAST_DLAST6 (0x1u << 13) /**< \brief (DMAC_LAST) Destination Last */
#define DMAC_LAST_SLAST7 (0x1u << 14) /**< \brief (DMAC_LAST) Source Last */
#define DMAC_LAST_DLAST7 (0x1u << 15) /**< \brief (DMAC_LAST) Destination Last */
/* -------- DMAC_EBCIER : (DMAC Offset: 0x018) DMAC Error, Chained Buffer Transfer Completed Interrupt and Buffer Transfer Completed Interrupt Enable register. -------- */
#define DMAC_EBCIER_BTC0 (0x1u << 0) /**< \brief (DMAC_EBCIER) Buffer Transfer Completed [7:0] */
#define DMAC_EBCIER_BTC1 (0x1u << 1) /**< \brief (DMAC_EBCIER) Buffer Transfer Completed [7:0] */
#define DMAC_EBCIER_BTC2 (0x1u << 2) /**< \brief (DMAC_EBCIER) Buffer Transfer Completed [7:0] */
#define DMAC_EBCIER_BTC3 (0x1u << 3) /**< \brief (DMAC_EBCIER) Buffer Transfer Completed [7:0] */
#define DMAC_EBCIER_BTC4 (0x1u << 4) /**< \brief (DMAC_EBCIER) Buffer Transfer Completed [7:0] */
#define DMAC_EBCIER_BTC5 (0x1u << 5) /**< \brief (DMAC_EBCIER) Buffer Transfer Completed [7:0] */
#define DMAC_EBCIER_BTC6 (0x1u << 6) /**< \brief (DMAC_EBCIER) Buffer Transfer Completed [7:0] */
#define DMAC_EBCIER_BTC7 (0x1u << 7) /**< \brief (DMAC_EBCIER) Buffer Transfer Completed [7:0] */
#define DMAC_EBCIER_CBTC0 (0x1u << 8) /**< \brief (DMAC_EBCIER) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCIER_CBTC1 (0x1u << 9) /**< \brief (DMAC_EBCIER) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCIER_CBTC2 (0x1u << 10) /**< \brief (DMAC_EBCIER) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCIER_CBTC3 (0x1u << 11) /**< \brief (DMAC_EBCIER) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCIER_CBTC4 (0x1u << 12) /**< \brief (DMAC_EBCIER) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCIER_CBTC5 (0x1u << 13) /**< \brief (DMAC_EBCIER) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCIER_CBTC6 (0x1u << 14) /**< \brief (DMAC_EBCIER) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCIER_CBTC7 (0x1u << 15) /**< \brief (DMAC_EBCIER) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCIER_ERR0 (0x1u << 16) /**< \brief (DMAC_EBCIER) Access Error [7:0] */
#define DMAC_EBCIER_ERR1 (0x1u << 17) /**< \brief (DMAC_EBCIER) Access Error [7:0] */
#define DMAC_EBCIER_ERR2 (0x1u << 18) /**< \brief (DMAC_EBCIER) Access Error [7:0] */
#define DMAC_EBCIER_ERR3 (0x1u << 19) /**< \brief (DMAC_EBCIER) Access Error [7:0] */
#define DMAC_EBCIER_ERR4 (0x1u << 20) /**< \brief (DMAC_EBCIER) Access Error [7:0] */
#define DMAC_EBCIER_ERR5 (0x1u << 21) /**< \brief (DMAC_EBCIER) Access Error [7:0] */
#define DMAC_EBCIER_ERR6 (0x1u << 22) /**< \brief (DMAC_EBCIER) Access Error [7:0] */
#define DMAC_EBCIER_ERR7 (0x1u << 23) /**< \brief (DMAC_EBCIER) Access Error [7:0] */
#define DMAC_EBCIER_DICERR0 (0x1u << 24) /**< \brief (DMAC_EBCIER) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCIER_DICERR1 (0x1u << 25) /**< \brief (DMAC_EBCIER) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCIER_DICERR2 (0x1u << 26) /**< \brief (DMAC_EBCIER) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCIER_DICERR3 (0x1u << 27) /**< \brief (DMAC_EBCIER) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCIER_DICERR4 (0x1u << 28) /**< \brief (DMAC_EBCIER) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCIER_DICERR5 (0x1u << 29) /**< \brief (DMAC_EBCIER) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCIER_DICERR6 (0x1u << 30) /**< \brief (DMAC_EBCIER) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCIER_DICERR7 (0x1u << 31) /**< \brief (DMAC_EBCIER) Descriptor Integrity Check Error [7:0] */
/* -------- DMAC_EBCIDR : (DMAC Offset: 0x01C) DMAC Error, Chained Buffer Transfer Completed Interrupt and Buffer Transfer Completed Interrupt Disable register. -------- */
#define DMAC_EBCIDR_BTC0 (0x1u << 0) /**< \brief (DMAC_EBCIDR) Buffer Transfer Completed [7:0] */
#define DMAC_EBCIDR_BTC1 (0x1u << 1) /**< \brief (DMAC_EBCIDR) Buffer Transfer Completed [7:0] */
#define DMAC_EBCIDR_BTC2 (0x1u << 2) /**< \brief (DMAC_EBCIDR) Buffer Transfer Completed [7:0] */
#define DMAC_EBCIDR_BTC3 (0x1u << 3) /**< \brief (DMAC_EBCIDR) Buffer Transfer Completed [7:0] */
#define DMAC_EBCIDR_BTC4 (0x1u << 4) /**< \brief (DMAC_EBCIDR) Buffer Transfer Completed [7:0] */
#define DMAC_EBCIDR_BTC5 (0x1u << 5) /**< \brief (DMAC_EBCIDR) Buffer Transfer Completed [7:0] */
#define DMAC_EBCIDR_BTC6 (0x1u << 6) /**< \brief (DMAC_EBCIDR) Buffer Transfer Completed [7:0] */
#define DMAC_EBCIDR_BTC7 (0x1u << 7) /**< \brief (DMAC_EBCIDR) Buffer Transfer Completed [7:0] */
#define DMAC_EBCIDR_CBTC0 (0x1u << 8) /**< \brief (DMAC_EBCIDR) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCIDR_CBTC1 (0x1u << 9) /**< \brief (DMAC_EBCIDR) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCIDR_CBTC2 (0x1u << 10) /**< \brief (DMAC_EBCIDR) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCIDR_CBTC3 (0x1u << 11) /**< \brief (DMAC_EBCIDR) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCIDR_CBTC4 (0x1u << 12) /**< \brief (DMAC_EBCIDR) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCIDR_CBTC5 (0x1u << 13) /**< \brief (DMAC_EBCIDR) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCIDR_CBTC6 (0x1u << 14) /**< \brief (DMAC_EBCIDR) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCIDR_CBTC7 (0x1u << 15) /**< \brief (DMAC_EBCIDR) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCIDR_ERR0 (0x1u << 16) /**< \brief (DMAC_EBCIDR) Access Error [7:0] */
#define DMAC_EBCIDR_ERR1 (0x1u << 17) /**< \brief (DMAC_EBCIDR) Access Error [7:0] */
#define DMAC_EBCIDR_ERR2 (0x1u << 18) /**< \brief (DMAC_EBCIDR) Access Error [7:0] */
#define DMAC_EBCIDR_ERR3 (0x1u << 19) /**< \brief (DMAC_EBCIDR) Access Error [7:0] */
#define DMAC_EBCIDR_ERR4 (0x1u << 20) /**< \brief (DMAC_EBCIDR) Access Error [7:0] */
#define DMAC_EBCIDR_ERR5 (0x1u << 21) /**< \brief (DMAC_EBCIDR) Access Error [7:0] */
#define DMAC_EBCIDR_ERR6 (0x1u << 22) /**< \brief (DMAC_EBCIDR) Access Error [7:0] */
#define DMAC_EBCIDR_ERR7 (0x1u << 23) /**< \brief (DMAC_EBCIDR) Access Error [7:0] */
#define DMAC_EBCIDR_DICERR0 (0x1u << 24) /**< \brief (DMAC_EBCIDR) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCIDR_DICERR1 (0x1u << 25) /**< \brief (DMAC_EBCIDR) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCIDR_DICERR2 (0x1u << 26) /**< \brief (DMAC_EBCIDR) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCIDR_DICERR3 (0x1u << 27) /**< \brief (DMAC_EBCIDR) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCIDR_DICERR4 (0x1u << 28) /**< \brief (DMAC_EBCIDR) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCIDR_DICERR5 (0x1u << 29) /**< \brief (DMAC_EBCIDR) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCIDR_DICERR6 (0x1u << 30) /**< \brief (DMAC_EBCIDR) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCIDR_DICERR7 (0x1u << 31) /**< \brief (DMAC_EBCIDR) Descriptor Integrity Check Error [7:0] */
/* -------- DMAC_EBCIMR : (DMAC Offset: 0x020) DMAC Error, Chained Buffer Transfer Completed Interrupt and Buffer transfer completed Mask Register. -------- */
#define DMAC_EBCIMR_BTC0 (0x1u << 0) /**< \brief (DMAC_EBCIMR) Buffer Transfer Completed [7:0] */
#define DMAC_EBCIMR_BTC1 (0x1u << 1) /**< \brief (DMAC_EBCIMR) Buffer Transfer Completed [7:0] */
#define DMAC_EBCIMR_BTC2 (0x1u << 2) /**< \brief (DMAC_EBCIMR) Buffer Transfer Completed [7:0] */
#define DMAC_EBCIMR_BTC3 (0x1u << 3) /**< \brief (DMAC_EBCIMR) Buffer Transfer Completed [7:0] */
#define DMAC_EBCIMR_BTC4 (0x1u << 4) /**< \brief (DMAC_EBCIMR) Buffer Transfer Completed [7:0] */
#define DMAC_EBCIMR_BTC5 (0x1u << 5) /**< \brief (DMAC_EBCIMR) Buffer Transfer Completed [7:0] */
#define DMAC_EBCIMR_BTC6 (0x1u << 6) /**< \brief (DMAC_EBCIMR) Buffer Transfer Completed [7:0] */
#define DMAC_EBCIMR_BTC7 (0x1u << 7) /**< \brief (DMAC_EBCIMR) Buffer Transfer Completed [7:0] */
#define DMAC_EBCIMR_CBTC0 (0x1u << 8) /**< \brief (DMAC_EBCIMR) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCIMR_CBTC1 (0x1u << 9) /**< \brief (DMAC_EBCIMR) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCIMR_CBTC2 (0x1u << 10) /**< \brief (DMAC_EBCIMR) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCIMR_CBTC3 (0x1u << 11) /**< \brief (DMAC_EBCIMR) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCIMR_CBTC4 (0x1u << 12) /**< \brief (DMAC_EBCIMR) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCIMR_CBTC5 (0x1u << 13) /**< \brief (DMAC_EBCIMR) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCIMR_CBTC6 (0x1u << 14) /**< \brief (DMAC_EBCIMR) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCIMR_CBTC7 (0x1u << 15) /**< \brief (DMAC_EBCIMR) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCIMR_ERR0 (0x1u << 16) /**< \brief (DMAC_EBCIMR) Access Error [7:0] */
#define DMAC_EBCIMR_ERR1 (0x1u << 17) /**< \brief (DMAC_EBCIMR) Access Error [7:0] */
#define DMAC_EBCIMR_ERR2 (0x1u << 18) /**< \brief (DMAC_EBCIMR) Access Error [7:0] */
#define DMAC_EBCIMR_ERR3 (0x1u << 19) /**< \brief (DMAC_EBCIMR) Access Error [7:0] */
#define DMAC_EBCIMR_ERR4 (0x1u << 20) /**< \brief (DMAC_EBCIMR) Access Error [7:0] */
#define DMAC_EBCIMR_ERR5 (0x1u << 21) /**< \brief (DMAC_EBCIMR) Access Error [7:0] */
#define DMAC_EBCIMR_ERR6 (0x1u << 22) /**< \brief (DMAC_EBCIMR) Access Error [7:0] */
#define DMAC_EBCIMR_ERR7 (0x1u << 23) /**< \brief (DMAC_EBCIMR) Access Error [7:0] */
#define DMAC_EBCIMR_DICERR0 (0x1u << 24) /**< \brief (DMAC_EBCIMR) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCIMR_DICERR1 (0x1u << 25) /**< \brief (DMAC_EBCIMR) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCIMR_DICERR2 (0x1u << 26) /**< \brief (DMAC_EBCIMR) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCIMR_DICERR3 (0x1u << 27) /**< \brief (DMAC_EBCIMR) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCIMR_DICERR4 (0x1u << 28) /**< \brief (DMAC_EBCIMR) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCIMR_DICERR5 (0x1u << 29) /**< \brief (DMAC_EBCIMR) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCIMR_DICERR6 (0x1u << 30) /**< \brief (DMAC_EBCIMR) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCIMR_DICERR7 (0x1u << 31) /**< \brief (DMAC_EBCIMR) Descriptor Integrity Check Error [7:0] */
/* -------- DMAC_EBCISR : (DMAC Offset: 0x024) DMAC Error, Chained Buffer Transfer Completed Interrupt and Buffer transfer completed Status Register. -------- */
#define DMAC_EBCISR_BTC0 (0x1u << 0) /**< \brief (DMAC_EBCISR) Buffer Transfer Completed [7:0] */
#define DMAC_EBCISR_BTC1 (0x1u << 1) /**< \brief (DMAC_EBCISR) Buffer Transfer Completed [7:0] */
#define DMAC_EBCISR_BTC2 (0x1u << 2) /**< \brief (DMAC_EBCISR) Buffer Transfer Completed [7:0] */
#define DMAC_EBCISR_BTC3 (0x1u << 3) /**< \brief (DMAC_EBCISR) Buffer Transfer Completed [7:0] */
#define DMAC_EBCISR_BTC4 (0x1u << 4) /**< \brief (DMAC_EBCISR) Buffer Transfer Completed [7:0] */
#define DMAC_EBCISR_BTC5 (0x1u << 5) /**< \brief (DMAC_EBCISR) Buffer Transfer Completed [7:0] */
#define DMAC_EBCISR_BTC6 (0x1u << 6) /**< \brief (DMAC_EBCISR) Buffer Transfer Completed [7:0] */
#define DMAC_EBCISR_BTC7 (0x1u << 7) /**< \brief (DMAC_EBCISR) Buffer Transfer Completed [7:0] */
#define DMAC_EBCISR_CBTC0 (0x1u << 8) /**< \brief (DMAC_EBCISR) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCISR_CBTC1 (0x1u << 9) /**< \brief (DMAC_EBCISR) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCISR_CBTC2 (0x1u << 10) /**< \brief (DMAC_EBCISR) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCISR_CBTC3 (0x1u << 11) /**< \brief (DMAC_EBCISR) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCISR_CBTC4 (0x1u << 12) /**< \brief (DMAC_EBCISR) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCISR_CBTC5 (0x1u << 13) /**< \brief (DMAC_EBCISR) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCISR_CBTC6 (0x1u << 14) /**< \brief (DMAC_EBCISR) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCISR_CBTC7 (0x1u << 15) /**< \brief (DMAC_EBCISR) Chained Buffer Transfer Completed [7:0] */
#define DMAC_EBCISR_ERR0 (0x1u << 16) /**< \brief (DMAC_EBCISR) Access Error [7:0] */
#define DMAC_EBCISR_ERR1 (0x1u << 17) /**< \brief (DMAC_EBCISR) Access Error [7:0] */
#define DMAC_EBCISR_ERR2 (0x1u << 18) /**< \brief (DMAC_EBCISR) Access Error [7:0] */
#define DMAC_EBCISR_ERR3 (0x1u << 19) /**< \brief (DMAC_EBCISR) Access Error [7:0] */
#define DMAC_EBCISR_ERR4 (0x1u << 20) /**< \brief (DMAC_EBCISR) Access Error [7:0] */
#define DMAC_EBCISR_ERR5 (0x1u << 21) /**< \brief (DMAC_EBCISR) Access Error [7:0] */
#define DMAC_EBCISR_ERR6 (0x1u << 22) /**< \brief (DMAC_EBCISR) Access Error [7:0] */
#define DMAC_EBCISR_ERR7 (0x1u << 23) /**< \brief (DMAC_EBCISR) Access Error [7:0] */
#define DMAC_EBCISR_DICERR0 (0x1u << 24) /**< \brief (DMAC_EBCISR) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCISR_DICERR1 (0x1u << 25) /**< \brief (DMAC_EBCISR) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCISR_DICERR2 (0x1u << 26) /**< \brief (DMAC_EBCISR) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCISR_DICERR3 (0x1u << 27) /**< \brief (DMAC_EBCISR) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCISR_DICERR4 (0x1u << 28) /**< \brief (DMAC_EBCISR) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCISR_DICERR5 (0x1u << 29) /**< \brief (DMAC_EBCISR) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCISR_DICERR6 (0x1u << 30) /**< \brief (DMAC_EBCISR) Descriptor Integrity Check Error [7:0] */
#define DMAC_EBCISR_DICERR7 (0x1u << 31) /**< \brief (DMAC_EBCISR) Descriptor Integrity Check Error [7:0] */
/* -------- DMAC_CHER : (DMAC Offset: 0x028) DMAC Channel Handler Enable Register -------- */
#define DMAC_CHER_ENA0 (0x1u << 0) /**< \brief (DMAC_CHER) Enable [7:0] */
#define DMAC_CHER_ENA1 (0x1u << 1) /**< \brief (DMAC_CHER) Enable [7:0] */
#define DMAC_CHER_ENA2 (0x1u << 2) /**< \brief (DMAC_CHER) Enable [7:0] */
#define DMAC_CHER_ENA3 (0x1u << 3) /**< \brief (DMAC_CHER) Enable [7:0] */
#define DMAC_CHER_ENA4 (0x1u << 4) /**< \brief (DMAC_CHER) Enable [7:0] */
#define DMAC_CHER_ENA5 (0x1u << 5) /**< \brief (DMAC_CHER) Enable [7:0] */
#define DMAC_CHER_ENA6 (0x1u << 6) /**< \brief (DMAC_CHER) Enable [7:0] */
#define DMAC_CHER_ENA7 (0x1u << 7) /**< \brief (DMAC_CHER) Enable [7:0] */
#define DMAC_CHER_SUSP0 (0x1u << 8) /**< \brief (DMAC_CHER) Suspend [7:0] */
#define DMAC_CHER_SUSP1 (0x1u << 9) /**< \brief (DMAC_CHER) Suspend [7:0] */
#define DMAC_CHER_SUSP2 (0x1u << 10) /**< \brief (DMAC_CHER) Suspend [7:0] */
#define DMAC_CHER_SUSP3 (0x1u << 11) /**< \brief (DMAC_CHER) Suspend [7:0] */
#define DMAC_CHER_SUSP4 (0x1u << 12) /**< \brief (DMAC_CHER) Suspend [7:0] */
#define DMAC_CHER_SUSP5 (0x1u << 13) /**< \brief (DMAC_CHER) Suspend [7:0] */
#define DMAC_CHER_SUSP6 (0x1u << 14) /**< \brief (DMAC_CHER) Suspend [7:0] */
#define DMAC_CHER_SUSP7 (0x1u << 15) /**< \brief (DMAC_CHER) Suspend [7:0] */
#define DMAC_CHER_KEEP0 (0x1u << 24) /**< \brief (DMAC_CHER) Keep on [7:0] */
#define DMAC_CHER_KEEP1 (0x1u << 25) /**< \brief (DMAC_CHER) Keep on [7:0] */
#define DMAC_CHER_KEEP2 (0x1u << 26) /**< \brief (DMAC_CHER) Keep on [7:0] */
#define DMAC_CHER_KEEP3 (0x1u << 27) /**< \brief (DMAC_CHER) Keep on [7:0] */
#define DMAC_CHER_KEEP4 (0x1u << 28) /**< \brief (DMAC_CHER) Keep on [7:0] */
#define DMAC_CHER_KEEP5 (0x1u << 29) /**< \brief (DMAC_CHER) Keep on [7:0] */
#define DMAC_CHER_KEEP6 (0x1u << 30) /**< \brief (DMAC_CHER) Keep on [7:0] */
#define DMAC_CHER_KEEP7 (0x1u << 31) /**< \brief (DMAC_CHER) Keep on [7:0] */
/* -------- DMAC_CHDR : (DMAC Offset: 0x02C) DMAC Channel Handler Disable Register -------- */
#define DMAC_CHDR_DIS0 (0x1u << 0) /**< \brief (DMAC_CHDR) Disable [7:0] */
#define DMAC_CHDR_DIS1 (0x1u << 1) /**< \brief (DMAC_CHDR) Disable [7:0] */
#define DMAC_CHDR_DIS2 (0x1u << 2) /**< \brief (DMAC_CHDR) Disable [7:0] */
#define DMAC_CHDR_DIS3 (0x1u << 3) /**< \brief (DMAC_CHDR) Disable [7:0] */
#define DMAC_CHDR_DIS4 (0x1u << 4) /**< \brief (DMAC_CHDR) Disable [7:0] */
#define DMAC_CHDR_DIS5 (0x1u << 5) /**< \brief (DMAC_CHDR) Disable [7:0] */
#define DMAC_CHDR_DIS6 (0x1u << 6) /**< \brief (DMAC_CHDR) Disable [7:0] */
#define DMAC_CHDR_DIS7 (0x1u << 7) /**< \brief (DMAC_CHDR) Disable [7:0] */
#define DMAC_CHDR_RES0 (0x1u << 8) /**< \brief (DMAC_CHDR) Resume [7:0] */
#define DMAC_CHDR_RES1 (0x1u << 9) /**< \brief (DMAC_CHDR) Resume [7:0] */
#define DMAC_CHDR_RES2 (0x1u << 10) /**< \brief (DMAC_CHDR) Resume [7:0] */
#define DMAC_CHDR_RES3 (0x1u << 11) /**< \brief (DMAC_CHDR) Resume [7:0] */
#define DMAC_CHDR_RES4 (0x1u << 12) /**< \brief (DMAC_CHDR) Resume [7:0] */
#define DMAC_CHDR_RES5 (0x1u << 13) /**< \brief (DMAC_CHDR) Resume [7:0] */
#define DMAC_CHDR_RES6 (0x1u << 14) /**< \brief (DMAC_CHDR) Resume [7:0] */
#define DMAC_CHDR_RES7 (0x1u << 15) /**< \brief (DMAC_CHDR) Resume [7:0] */
/* -------- DMAC_CHSR : (DMAC Offset: 0x030) DMAC Channel Handler Status Register -------- */
#define DMAC_CHSR_ENA0 (0x1u << 0) /**< \brief (DMAC_CHSR) Enable [7:0] */
#define DMAC_CHSR_ENA1 (0x1u << 1) /**< \brief (DMAC_CHSR) Enable [7:0] */
#define DMAC_CHSR_ENA2 (0x1u << 2) /**< \brief (DMAC_CHSR) Enable [7:0] */
#define DMAC_CHSR_ENA3 (0x1u << 3) /**< \brief (DMAC_CHSR) Enable [7:0] */
#define DMAC_CHSR_ENA4 (0x1u << 4) /**< \brief (DMAC_CHSR) Enable [7:0] */
#define DMAC_CHSR_ENA5 (0x1u << 5) /**< \brief (DMAC_CHSR) Enable [7:0] */
#define DMAC_CHSR_ENA6 (0x1u << 6) /**< \brief (DMAC_CHSR) Enable [7:0] */
#define DMAC_CHSR_ENA7 (0x1u << 7) /**< \brief (DMAC_CHSR) Enable [7:0] */
#define DMAC_CHSR_SUSP0 (0x1u << 8) /**< \brief (DMAC_CHSR) Suspend [7:0] */
#define DMAC_CHSR_SUSP1 (0x1u << 9) /**< \brief (DMAC_CHSR) Suspend [7:0] */
#define DMAC_CHSR_SUSP2 (0x1u << 10) /**< \brief (DMAC_CHSR) Suspend [7:0] */
#define DMAC_CHSR_SUSP3 (0x1u << 11) /**< \brief (DMAC_CHSR) Suspend [7:0] */
#define DMAC_CHSR_SUSP4 (0x1u << 12) /**< \brief (DMAC_CHSR) Suspend [7:0] */
#define DMAC_CHSR_SUSP5 (0x1u << 13) /**< \brief (DMAC_CHSR) Suspend [7:0] */
#define DMAC_CHSR_SUSP6 (0x1u << 14) /**< \brief (DMAC_CHSR) Suspend [7:0] */
#define DMAC_CHSR_SUSP7 (0x1u << 15) /**< \brief (DMAC_CHSR) Suspend [7:0] */
#define DMAC_CHSR_EMPT0 (0x1u << 16) /**< \brief (DMAC_CHSR) Empty [7:0] */
#define DMAC_CHSR_EMPT1 (0x1u << 17) /**< \brief (DMAC_CHSR) Empty [7:0] */
#define DMAC_CHSR_EMPT2 (0x1u << 18) /**< \brief (DMAC_CHSR) Empty [7:0] */
#define DMAC_CHSR_EMPT3 (0x1u << 19) /**< \brief (DMAC_CHSR) Empty [7:0] */
#define DMAC_CHSR_EMPT4 (0x1u << 20) /**< \brief (DMAC_CHSR) Empty [7:0] */
#define DMAC_CHSR_EMPT5 (0x1u << 21) /**< \brief (DMAC_CHSR) Empty [7:0] */
#define DMAC_CHSR_EMPT6 (0x1u << 22) /**< \brief (DMAC_CHSR) Empty [7:0] */
#define DMAC_CHSR_EMPT7 (0x1u << 23) /**< \brief (DMAC_CHSR) Empty [7:0] */
#define DMAC_CHSR_STAL0 (0x1u << 24) /**< \brief (DMAC_CHSR) Stalled [7:0] */
#define DMAC_CHSR_STAL1 (0x1u << 25) /**< \brief (DMAC_CHSR) Stalled [7:0] */
#define DMAC_CHSR_STAL2 (0x1u << 26) /**< \brief (DMAC_CHSR) Stalled [7:0] */
#define DMAC_CHSR_STAL3 (0x1u << 27) /**< \brief (DMAC_CHSR) Stalled [7:0] */
#define DMAC_CHSR_STAL4 (0x1u << 28) /**< \brief (DMAC_CHSR) Stalled [7:0] */
#define DMAC_CHSR_STAL5 (0x1u << 29) /**< \brief (DMAC_CHSR) Stalled [7:0] */
#define DMAC_CHSR_STAL6 (0x1u << 30) /**< \brief (DMAC_CHSR) Stalled [7:0] */
#define DMAC_CHSR_STAL7 (0x1u << 31) /**< \brief (DMAC_CHSR) Stalled [7:0] */
/* -------- DMAC_SADDR : (DMAC Offset: N/A) DMAC Channel Source Address Register -------- */
#define DMAC_SADDR_SADDR_Pos 0
#define DMAC_SADDR_SADDR_Msk (0xffffffffu << DMAC_SADDR_SADDR_Pos) /**< \brief (DMAC_SADDR) Channel x Source Address */
#define DMAC_SADDR_SADDR(value) ((DMAC_SADDR_SADDR_Msk & ((value) << DMAC_SADDR_SADDR_Pos)))
/* -------- DMAC_DADDR : (DMAC Offset: N/A) DMAC Channel Destination Address Register -------- */
#define DMAC_DADDR_DADDR_Pos 0
#define DMAC_DADDR_DADDR_Msk (0xffffffffu << DMAC_DADDR_DADDR_Pos) /**< \brief (DMAC_DADDR) Channel x Destination Address */
#define DMAC_DADDR_DADDR(value) ((DMAC_DADDR_DADDR_Msk & ((value) << DMAC_DADDR_DADDR_Pos)))
/* -------- DMAC_DSCR : (DMAC Offset: N/A) DMAC Channel Descriptor Address Register -------- */
#define DMAC_DSCR_DSCR_IF_Pos 0
#define DMAC_DSCR_DSCR_IF_Msk (0x3u << DMAC_DSCR_DSCR_IF_Pos) /**< \brief (DMAC_DSCR)  */
#define   DMAC_DSCR_DSCR_IF_AHB_IF0 (0x0u << 0) /**< \brief (DMAC_DSCR) The buffer transfer descriptor is fetched via AHB-Lite Interface 0 */
#define   DMAC_DSCR_DSCR_IF_AHB_IF1 (0x1u << 0) /**< \brief (DMAC_DSCR) The buffer transfer descriptor is fetched via AHB-Lite Interface 1 */
#define DMAC_DSCR_DSCR_Pos 2
#define DMAC_DSCR_DSCR_Msk (0x3fffffffu << DMAC_DSCR_DSCR_Pos) /**< \brief (DMAC_DSCR) Buffer Transfer Descriptor Address */
#define DMAC_DSCR_DSCR(value) ((DMAC_DSCR_DSCR_Msk & ((value) << DMAC_DSCR_DSCR_Pos)))
/* -------- DMAC_CTRLA : (DMAC Offset: N/A) DMAC Channel Control A Register -------- */
#define DMAC_CTRLA_BTSIZE_Pos 0
#define DMAC_CTRLA_BTSIZE_Msk (0xffffu << DMAC_CTRLA_BTSIZE_Pos) /**< \brief (DMAC_CTRLA) Buffer Transfer Size */
#define DMAC_CTRLA_BTSIZE(value) ((DMAC_CTRLA_BTSIZE_Msk & ((value) << DMAC_CTRLA_BTSIZE_Pos)))
#define DMAC_CTRLA_SCSIZE_Pos 16
#define DMAC_CTRLA_SCSIZE_Msk (0x7u << DMAC_CTRLA_SCSIZE_Pos) /**< \brief (DMAC_CTRLA) Source Chunk Transfer Size. */
#define   DMAC_CTRLA_SCSIZE_CHK_1 (0x0u << 16) /**< \brief (DMAC_CTRLA) 1 data transferred */
#define   DMAC_CTRLA_SCSIZE_CHK_4 (0x1u << 16) /**< \brief (DMAC_CTRLA) 4 data transferred */
#define   DMAC_CTRLA_SCSIZE_CHK_8 (0x2u << 16) /**< \brief (DMAC_CTRLA) 8 data transferred */
#define   DMAC_CTRLA_SCSIZE_CHK_16 (0x3u << 16) /**< \brief (DMAC_CTRLA) 16 data transferred */
#define   DMAC_CTRLA_SCSIZE_CHK_32 (0x4u << 16) /**< \brief (DMAC_CTRLA) 32 data transferred */
#define   DMAC_CTRLA_SCSIZE_CHK_64 (0x5u << 16) /**< \brief (DMAC_CTRLA) 64 data transferred */
#define   DMAC_CTRLA_SCSIZE_CHK_128 (0x6u << 16) /**< \brief (DMAC_CTRLA) 128 data transferred */
#define   DMAC_CTRLA_SCSIZE_CHK_256 (0x7u << 16) /**< \brief (DMAC_CTRLA) 256 data transferred */
#define DMAC_CTRLA_DCSIZE_Pos 20
#define DMAC_CTRLA_DCSIZE_Msk (0x7u << DMAC_CTRLA_DCSIZE_Pos) /**< \brief (DMAC_CTRLA) Destination Chunk Transfer Size */
#define   DMAC_CTRLA_DCSIZE_CHK_1 (0x0u << 20) /**< \brief (DMAC_CTRLA) 1 data transferred */
#define   DMAC_CTRLA_DCSIZE_CHK_4 (0x1u << 20) /**< \brief (DMAC_CTRLA) 4 data transferred */
#define   DMAC_CTRLA_DCSIZE_CHK_8 (0x2u << 20) /**< \brief (DMAC_CTRLA) 8 data transferred */
#define   DMAC_CTRLA_DCSIZE_CHK_16 (0x3u << 20) /**< \brief (DMAC_CTRLA) 16 data transferred */
#define   DMAC_CTRLA_DCSIZE_CHK_32 (0x4u << 20) /**< \brief (DMAC_CTRLA) 32 data transferred */
#define   DMAC_CTRLA_DCSIZE_CHK_64 (0x5u << 20) /**< \brief (DMAC_CTRLA) 64 data transferred */
#define   DMAC_CTRLA_DCSIZE_CHK_128 (0x6u << 20) /**< \brief (DMAC_CTRLA) 128 data transferred */
#define   DMAC_CTRLA_DCSIZE_CHK_256 (0x7u << 20) /**< \brief (DMAC_CTRLA) 256 data transferred */
#define DMAC_CTRLA_SRC_WIDTH_Pos 24
#define DMAC_CTRLA_SRC_WIDTH_Msk (0x3u << DMAC_CTRLA_SRC_WIDTH_Pos) /**< \brief (DMAC_CTRLA) Transfer Width for the Source */
#define   DMAC_CTRLA_SRC_WIDTH_BYTE (0x0u << 24) /**< \brief (DMAC_CTRLA) the transfer size is set to 8-bit width */
#define   DMAC_CTRLA_SRC_WIDTH_HALF_WORD (0x1u << 24) /**< \brief (DMAC_CTRLA) the transfer size is set to 16-bit width */
#define   DMAC_CTRLA_SRC_WIDTH_WORD (0x2u << 24) /**< \brief (DMAC_CTRLA) the transfer size is set to 32-bit width */
#define DMAC_CTRLA_DST_WIDTH_Pos 28
#define DMAC_CTRLA_DST_WIDTH_Msk (0x3u << DMAC_CTRLA_DST_WIDTH_Pos) /**< \brief (DMAC_CTRLA) Transfer Width for the Destination */
#define   DMAC_CTRLA_DST_WIDTH_BYTE (0x0u << 28) /**< \brief (DMAC_CTRLA) the transfer size is set to 8-bit width */
#define   DMAC_CTRLA_DST_WIDTH_HALF_WORD (0x1u << 28) /**< \brief (DMAC_CTRLA) the transfer size is set to 16-bit width */
#define   DMAC_CTRLA_DST_WIDTH_WORD (0x2u << 28) /**< \brief (DMAC_CTRLA) the transfer size is set to 32-bit width */
#define DMAC_CTRLA_DONE (0x1u << 31) /**< \brief (DMAC_CTRLA)  */
/* -------- DMAC_CTRLB : (DMAC Offset: N/A) DMAC Channel Control B Register -------- */
#define DMAC_CTRLB_SIF_Pos 0
#define DMAC_CTRLB_SIF_Msk (0x3u << DMAC_CTRLB_SIF_Pos) /**< \brief (DMAC_CTRLB) Source Interface Selection Field */
#define   DMAC_CTRLB_SIF_AHB_IF0 (0x0u << 0) /**< \brief (DMAC_CTRLB) The source transfer is done via AHB-Lite Interface 0 */
#define   DMAC_CTRLB_SIF_AHB_IF1 (0x1u << 0) /**< \brief (DMAC_CTRLB) The source transfer is done via AHB-Lite Interface 1 */
#define DMAC_CTRLB_DIF_Pos 4
#define DMAC_CTRLB_DIF_Msk (0x3u << DMAC_CTRLB_DIF_Pos) /**< \brief (DMAC_CTRLB) Destination Interface Selection Field */
#define   DMAC_CTRLB_DIF_AHB_IF0 (0x0u << 4) /**< \brief (DMAC_CTRLB) The destination transfer is done via AHB-Lite Interface 0 */
#define   DMAC_CTRLB_DIF_AHB_IF1 (0x1u << 4) /**< \brief (DMAC_CTRLB) The destination transfer is done via AHB-Lite Interface 1 */
#define DMAC_CTRLB_SRC_PIP (0x1u << 8) /**< \brief (DMAC_CTRLB) Source Picture-in-Picture Mode */
#define   DMAC_CTRLB_SRC_PIP_DISABLE (0x0u << 8) /**< \brief (DMAC_CTRLB) Picture-in-Picture mode is disabled. The source data area is contiguous. */
#define   DMAC_CTRLB_SRC_PIP_ENABLE (0x1u << 8) /**< \brief (DMAC_CTRLB) Picture-in-Picture mode is enabled. When the source PIP counter reaches the programmable boundary, the address is automatically incremented by a user defined amount. */
#define DMAC_CTRLB_DST_PIP (0x1u << 12) /**< \brief (DMAC_CTRLB) Destination Picture-in-Picture Mode */
#define   DMAC_CTRLB_DST_PIP_DISABLE (0x0u << 12) /**< \brief (DMAC_CTRLB) Picture-in-Picture mode is disabled. The Destination data area is contiguous. */
#define   DMAC_CTRLB_DST_PIP_ENABLE (0x1u << 12) /**< \brief (DMAC_CTRLB) Picture-in-Picture mode is enabled. When the Destination PIP counter reaches the programmable boundary the address is automatically incremented by a user-defined amount. */
#define DMAC_CTRLB_SRC_DSCR (0x1u << 16) /**< \brief (DMAC_CTRLB) Source Address Descriptor */
#define   DMAC_CTRLB_SRC_DSCR_FETCH_FROM_MEM (0x0u << 16) /**< \brief (DMAC_CTRLB) Source address is updated when the descriptor is fetched from the memory. */
#define   DMAC_CTRLB_SRC_DSCR_FETCH_DISABLE (0x1u << 16) /**< \brief (DMAC_CTRLB) Buffer Descriptor Fetch operation is disabled for the source. */
#define DMAC_CTRLB_DST_DSCR (0x1u << 20) /**< \brief (DMAC_CTRLB) Destination Address Descriptor */
#define   DMAC_CTRLB_DST_DSCR_FETCH_FROM_MEM (0x0u << 20) /**< \brief (DMAC_CTRLB) Destination address is updated when the descriptor is fetched from the memory. */
#define   DMAC_CTRLB_DST_DSCR_FETCH_DISABLE (0x1u << 20) /**< \brief (DMAC_CTRLB) Buffer Descriptor Fetch operation is disabled for the destination. */
#define DMAC_CTRLB_FC_Pos 21
#define DMAC_CTRLB_FC_Msk (0x7u << DMAC_CTRLB_FC_Pos) /**< \brief (DMAC_CTRLB) Flow Control */
#define   DMAC_CTRLB_FC_MEM2MEM_DMA_FC (0x0u << 21) /**< \brief (DMAC_CTRLB) Memory-to-Memory Transfer DMAC is flow controller */
#define   DMAC_CTRLB_FC_MEM2PER_DMA_FC (0x1u << 21) /**< \brief (DMAC_CTRLB) Memory-to-Peripheral Transfer DMAC is flow controller */
#define   DMAC_CTRLB_FC_PER2MEM_DMA_FC (0x2u << 21) /**< \brief (DMAC_CTRLB) Peripheral-to-Memory Transfer DMAC is flow controller */
#define   DMAC_CTRLB_FC_PER2PER_DMA_FC (0x3u << 21) /**< \brief (DMAC_CTRLB) Peripheral-to-Peripheral Transfer DMAC is flow controller */
#define DMAC_CTRLB_SRC_INCR_Pos 24
#define DMAC_CTRLB_SRC_INCR_Msk (0x3u << DMAC_CTRLB_SRC_INCR_Pos) /**< \brief (DMAC_CTRLB) Incrementing, Decrementing or Fixed Address for the Source */
#define   DMAC_CTRLB_SRC_INCR_INCREMENTING (0x0u << 24) /**< \brief (DMAC_CTRLB) The source address is incremented */
#define   DMAC_CTRLB_SRC_INCR_DECREMENTING (0x1u << 24) /**< \brief (DMAC_CTRLB) The source address is decremented */
#define   DMAC_CTRLB_SRC_INCR_FIXED (0x2u << 24) /**< \brief (DMAC_CTRLB) The source address remains unchanged */
#define DMAC_CTRLB_DST_INCR_Pos 28
#define DMAC_CTRLB_DST_INCR_Msk (0x3u << DMAC_CTRLB_DST_INCR_Pos) /**< \brief (DMAC_CTRLB) Incrementing, Decrementing or Fixed Address for the Destination */
#define   DMAC_CTRLB_DST_INCR_INCREMENTING (0x0u << 28) /**< \brief (DMAC_CTRLB) The destination address is incremented */
#define   DMAC_CTRLB_DST_INCR_DECREMENTING (0x1u << 28) /**< \brief (DMAC_CTRLB) The destination address is decremented */
#define   DMAC_CTRLB_DST_INCR_FIXED (0x2u << 28) /**< \brief (DMAC_CTRLB) The destination address remains unchanged */
#define DMAC_CTRLB_IEN (0x1u << 30) /**< \brief (DMAC_CTRLB)  */
#define DMAC_CTRLB_AUTO (0x1u << 31) /**< \brief (DMAC_CTRLB) Automatic Multiple Buffer Transfer */
#define   DMAC_CTRLB_AUTO_DISABLE (0x0u << 31) /**< \brief (DMAC_CTRLB) Automatic multiple buffer transfer is disabled. */
#define   DMAC_CTRLB_AUTO_ENABLE (0x1u << 31) /**< \brief (DMAC_CTRLB) Automatic multiple buffer transfer is enabled. This bit enables replay mode or contiguous mode when several buffers are transferred. */
/* -------- DMAC_CFG : (DMAC Offset: N/A) DMAC Channel Configuration Register -------- */
#define DMAC_CFG_SRC_PER_Pos 0
#define DMAC_CFG_SRC_PER_Msk (0xfu << DMAC_CFG_SRC_PER_Pos) /**< \brief (DMAC_CFG) Source with Peripheral identifier */
#define DMAC_CFG_SRC_PER(value) ((DMAC_CFG_SRC_PER_Msk & ((value) << DMAC_CFG_SRC_PER_Pos)))
#define DMAC_CFG_DST_PER_Pos 4
#define DMAC_CFG_DST_PER_Msk (0xfu << DMAC_CFG_DST_PER_Pos) /**< \brief (DMAC_CFG) Destination with Peripheral identifier */
#define DMAC_CFG_DST_PER(value) ((DMAC_CFG_DST_PER_Msk & ((value) << DMAC_CFG_DST_PER_Pos)))
#define DMAC_CFG_SRC_REP (0x1u << 8) /**< \brief (DMAC_CFG) Source Reloaded from Previous */
#define   DMAC_CFG_SRC_REP_CONTIGUOUS_ADDR (0x0u << 8) /**< \brief (DMAC_CFG) When automatic mode is activated, source address is contiguous between two buffers. */
#define   DMAC_CFG_SRC_REP_RELOAD_ADDR (0x1u << 8) /**< \brief (DMAC_CFG) When automatic mode is activated, the source address and the control register are reloaded from previous transfer. */
#define DMAC_CFG_SRC_H2SEL (0x1u << 9) /**< \brief (DMAC_CFG) Software or Hardware Selection for the Source */
#define   DMAC_CFG_SRC_H2SEL_SW (0x0u << 9) /**< \brief (DMAC_CFG) Software handshaking interface is used to trigger a transfer request. */
#define   DMAC_CFG_SRC_H2SEL_HW (0x1u << 9) /**< \brief (DMAC_CFG) Hardware handshaking interface is used to trigger a transfer request. */
#define DMAC_CFG_SRC_PER_MSB_Pos 10
#define DMAC_CFG_SRC_PER_MSB_Msk (0x3u << DMAC_CFG_SRC_PER_MSB_Pos) /**< \brief (DMAC_CFG) SRC_PER Most Significant Bits */
#define DMAC_CFG_SRC_PER_MSB(value) ((DMAC_CFG_SRC_PER_MSB_Msk & ((value) << DMAC_CFG_SRC_PER_MSB_Pos)))
#define DMAC_CFG_DST_REP (0x1u << 12) /**< \brief (DMAC_CFG) Destination Reloaded from Previous */
#define   DMAC_CFG_DST_REP_CONTIGUOUS_ADDR (0x0u << 12) /**< \brief (DMAC_CFG) When automatic mode is activated, destination address is contiguous between two buffers. */
#define   DMAC_CFG_DST_REP_RELOAD_ADDR (0x1u << 12) /**< \brief (DMAC_CFG) When automatic mode is activated, the destination and the control register are reloaded from the pre-vious transfer. */
#define DMAC_CFG_DST_H2SEL (0x1u << 13) /**< \brief (DMAC_CFG) Software or Hardware Selection for the Destination */
#define   DMAC_CFG_DST_H2SEL_SW (0x0u << 13) /**< \brief (DMAC_CFG) Software handshaking interface is used to trigger a transfer request. */
#define   DMAC_CFG_DST_H2SEL_HW (0x1u << 13) /**< \brief (DMAC_CFG) Hardware handshaking interface is used to trigger a transfer request. */
#define DMAC_CFG_DST_PER_MSB_Pos 14
#define DMAC_CFG_DST_PER_MSB_Msk (0x3u << DMAC_CFG_DST_PER_MSB_Pos) /**< \brief (DMAC_CFG) DST_PER Most Significant Bits */
#define DMAC_CFG_DST_PER_MSB(value) ((DMAC_CFG_DST_PER_MSB_Msk & ((value) << DMAC_CFG_DST_PER_MSB_Pos)))
#define DMAC_CFG_SOD (0x1u << 16) /**< \brief (DMAC_CFG) Stop On Done */
#define   DMAC_CFG_SOD_DISABLE (0x0u << 16) /**< \brief (DMAC_CFG) STOP ON DONE disabled, the descriptor fetch operation ignores DONE Field of CTRLA register. */
#define   DMAC_CFG_SOD_ENABLE (0x1u << 16) /**< \brief (DMAC_CFG) STOP ON DONE activated, the DMAC module is automatically disabled if DONE FIELD is set to 1. */
#define DMAC_CFG_LOCK_IF (0x1u << 20) /**< \brief (DMAC_CFG) Interface Lock */
#define   DMAC_CFG_LOCK_IF_DISABLE (0x0u << 20) /**< \brief (DMAC_CFG) Interface Lock capability is disabled */
#define   DMAC_CFG_LOCK_IF_ENABLE (0x1u << 20) /**< \brief (DMAC_CFG) Interface Lock capability is enabled */
#define DMAC_CFG_LOCK_B (0x1u << 21) /**< \brief (DMAC_CFG) Bus Lock */
#define   DMAC_CFG_LOCK_B_DISABLE (0x0u << 21) /**< \brief (DMAC_CFG) AHB Bus Locking capability is disabled. */
#define DMAC_CFG_LOCK_IF_L (0x1u << 22) /**< \brief (DMAC_CFG) Master Interface Arbiter Lock */
#define   DMAC_CFG_LOCK_IF_L_CHUNK (0x0u << 22) /**< \brief (DMAC_CFG) The Master Interface Arbiter is locked by the channel x for a chunk transfer. */
#define   DMAC_CFG_LOCK_IF_L_BUFFER (0x1u << 22) /**< \brief (DMAC_CFG) The Master Interface Arbiter is locked by the channel x for a buffer transfer. */
#define DMAC_CFG_AHB_PROT_Pos 24
#define DMAC_CFG_AHB_PROT_Msk (0x7u << DMAC_CFG_AHB_PROT_Pos) /**< \brief (DMAC_CFG) AHB Protection */
#define DMAC_CFG_AHB_PROT(value) ((DMAC_CFG_AHB_PROT_Msk & ((value) << DMAC_CFG_AHB_PROT_Pos)))
#define DMAC_CFG_FIFOCFG_Pos 28
#define DMAC_CFG_FIFOCFG_Msk (0x3u << DMAC_CFG_FIFOCFG_Pos) /**< \brief (DMAC_CFG) FIFO Configuration */
#define   DMAC_CFG_FIFOCFG_ALAP_CFG (0x0u << 28) /**< \brief (DMAC_CFG) The largest defined length AHB burst is performed on the destination AHB interface. */
#define   DMAC_CFG_FIFOCFG_HALF_CFG (0x1u << 28) /**< \brief (DMAC_CFG) When half FIFO size is available/filled, a source/destination request is serviced. */
#define   DMAC_CFG_FIFOCFG_ASAP_CFG (0x2u << 28) /**< \brief (DMAC_CFG) When there is enough space/data available to perform a single AHB access, then the request is serviced. */
/* -------- DMAC_SPIP : (DMAC Offset: N/A) DMAC Channel Source Picture-in-Picture Configuration Register -------- */
#define DMAC_SPIP_SPIP_HOLE_Pos 0
#define DMAC_SPIP_SPIP_HOLE_Msk (0xffffu << DMAC_SPIP_SPIP_HOLE_Pos) /**< \brief (DMAC_SPIP) Source Picture-in-Picture Hole */
#define DMAC_SPIP_SPIP_HOLE(value) ((DMAC_SPIP_SPIP_HOLE_Msk & ((value) << DMAC_SPIP_SPIP_HOLE_Pos)))
#define DMAC_SPIP_SPIP_BOUNDARY_Pos 16
#define DMAC_SPIP_SPIP_BOUNDARY_Msk (0x3ffu << DMAC_SPIP_SPIP_BOUNDARY_Pos) /**< \brief (DMAC_SPIP) Source Picture-in-Picture Boundary */
#define DMAC_SPIP_SPIP_BOUNDARY(value) ((DMAC_SPIP_SPIP_BOUNDARY_Msk & ((value) << DMAC_SPIP_SPIP_BOUNDARY_Pos)))
/* -------- DMAC_DPIP : (DMAC Offset: N/A) DMAC Channel Destination Picture-in-Picture Configuration Register -------- */
#define DMAC_DPIP_DPIP_HOLE_Pos 0
#define DMAC_DPIP_DPIP_HOLE_Msk (0xffffu << DMAC_DPIP_DPIP_HOLE_Pos) /**< \brief (DMAC_DPIP) Destination Picture-in-Picture Hole */
#define DMAC_DPIP_DPIP_HOLE(value) ((DMAC_DPIP_DPIP_HOLE_Msk & ((value) << DMAC_DPIP_DPIP_HOLE_Pos)))
#define DMAC_DPIP_DPIP_BOUNDARY_Pos 16
#define DMAC_DPIP_DPIP_BOUNDARY_Msk (0x3ffu << DMAC_DPIP_DPIP_BOUNDARY_Pos) /**< \brief (DMAC_DPIP) Destination Picture-in-Picture Boundary */
#define DMAC_DPIP_DPIP_BOUNDARY(value) ((DMAC_DPIP_DPIP_BOUNDARY_Msk & ((value) << DMAC_DPIP_DPIP_BOUNDARY_Pos)))
/* -------- DMAC_WPMR : (DMAC Offset: 0x1E4) DMAC Write Protect Mode Register -------- */
#define DMAC_WPMR_WPEN (0x1u << 0) /**< \brief (DMAC_WPMR) Write Protect Enable */
#define DMAC_WPMR_WPKEY_Pos 8
#define DMAC_WPMR_WPKEY_Msk (0xffffffu << DMAC_WPMR_WPKEY_Pos) /**< \brief (DMAC_WPMR) Write Protect KEY */
#define DMAC_WPMR_WPKEY(value) ((DMAC_WPMR_WPKEY_Msk & ((value) << DMAC_WPMR_WPKEY_Pos)))
/* -------- DMAC_WPSR : (DMAC Offset: 0x1E8) DMAC Write Protect Status Register -------- */
#define DMAC_WPSR_WPVS (0x1u << 0) /**< \brief (DMAC_WPSR) Write Protect Violation Status */
#define DMAC_WPSR_WPVSRC_Pos 8
#define DMAC_WPSR_WPVSRC_Msk (0xffffu << DMAC_WPSR_WPVSRC_Pos) /**< \brief (DMAC_WPSR) Write Protect Violation Source */

/*@}*/

/* ============================================================================= */
/**  SOFTWARE API DEFINITION FOR Fuse Controller */
/* ============================================================================= */
/** \addtogroup SAM9N12_FUSE Fuse Controller */
/*@{*/

#ifndef __ASSEMBLY__
/** \brief Fuse hardware registers */
typedef struct {
  WoReg FUSE_CR;    /**< \brief (Fuse Offset: 0x00) Fuse Control Register */
  WoReg FUSE_MR;    /**< \brief (Fuse Offset: 0x04) Fuse Mode Register */
  RwReg FUSE_IR;    /**< \brief (Fuse Offset: 0x08) Fuse Index Register */
  WoReg FUSE_DR;    /**< \brief (Fuse Offset: 0x0C) Fuse Data Register */
  RoReg FUSE_SR[10]; /**< \brief (Fuse Offset: 0x10) Fuse Status Register */
} Fuse;
#endif /* __ASSEMBLY__ */
/* -------- FUSE_CR : (FUSE Offset: 0x00) Fuse Control Register -------- */
#define FUSE_CR_WRQ (0x1u << 0) /**< \brief (FUSE_CR) Write Request */
#define FUSE_CR_RRQ (0x1u << 1) /**< \brief (FUSE_CR) Read Request */
#define FUSE_CR_KEY_Pos 8
#define FUSE_CR_KEY_Msk (0xffu << FUSE_CR_KEY_Pos) /**< \brief (FUSE_CR) Key code */
#define   FUSE_CR_KEY_VALID (0xFBu << 8) /**< \brief (FUSE_CR) valid key. */
/* -------- FUSE_MR : (FUSE Offset: 0x04) Fuse Mode Register -------- */
#define FUSE_MR_MSK (0x1u << 0) /**< \brief (FUSE_MR) Mask Fuse Status Registers */
/* -------- FUSE_IR : (FUSE Offset: 0x08) Fuse Index Register -------- */
#define FUSE_IR_WS (0x1u << 0) /**< \brief (FUSE_IR) Write Status */
#define FUSE_IR_RS (0x1u << 1) /**< \brief (FUSE_IR) Read Status */
#define FUSE_IR_WSEL_Pos 8
#define FUSE_IR_WSEL_Msk (0xfu << FUSE_IR_WSEL_Pos) /**< \brief (FUSE_IR) Word Selection */
#define FUSE_IR_WSEL(value) ((FUSE_IR_WSEL_Msk & ((value) << FUSE_IR_WSEL_Pos)))
/* -------- FUSE_DR : (FUSE Offset: 0x0C) Fuse Data Register -------- */
#define FUSE_DR_DATA_Pos 0
#define FUSE_DR_DATA_Msk (0xffffffffu << FUSE_DR_DATA_Pos) /**< \brief (FUSE_DR) Data to Program */
#define FUSE_DR_DATA(value) ((FUSE_DR_DATA_Msk & ((value) << FUSE_DR_DATA_Pos)))
/* -------- FUSE_SR[8] : (FUSE Offset: 0x10) Fuse Status Register -------- */
#define FUSE_SR_FUSE_Pos 0
#define FUSE_SR_FUSE_Msk (0xffffffffu << FUSE_SR_FUSE_Pos) /**< \brief (FUSE_SR[8]) Fuse Status */

/*@}*/

/* ============================================================================= */
/**  SOFTWARE API DEFINITION FOR General Purpose Backup Register */
/* ============================================================================= */
/** \addtogroup SAM9N12_GPBR General Purpose Backup Register */
/*@{*/

#ifndef __ASSEMBLY__
/** \brief Gpbr hardware registers */
typedef struct {
  RwReg SYS_GPBR0; /**< \brief (Gpbr Offset: 0x0) General Purpose Backup Register 0 */
  RwReg SYS_GPBR1; /**< \brief (Gpbr Offset: 0x4) General Purpose Backup Register 1 */
  RwReg SYS_GPBR2; /**< \brief (Gpbr Offset: 0x8) General Purpose Backup Register 2 */
  RwReg SYS_GPBR3; /**< \brief (Gpbr Offset: 0xC) General Purpose Backup Register 3 */
} Gpbr;
#endif /* __ASSEMBLY__ */
/* -------- SYS_GPBR0 : (GPBR Offset: 0x0) General Purpose Backup Register 0 -------- */
#define SYS_GPBR0_GPBR_VALUE0_Pos 0
#define SYS_GPBR0_GPBR_VALUE0_Msk (0xffffffffu << SYS_GPBR0_GPBR_VALUE0_Pos) /**< \brief (SYS_GPBR0) Value of GPBR x */
#define SYS_GPBR0_GPBR_VALUE0(value) ((SYS_GPBR0_GPBR_VALUE0_Msk & ((value) << SYS_GPBR0_GPBR_VALUE0_Pos)))
/* -------- SYS_GPBR1 : (GPBR Offset: 0x4) General Purpose Backup Register 1 -------- */
#define SYS_GPBR1_GPBR_VALUE1_Pos 0
#define SYS_GPBR1_GPBR_VALUE1_Msk (0xffffffffu << SYS_GPBR1_GPBR_VALUE1_Pos) /**< \brief (SYS_GPBR1) Value of GPBR x */
#define SYS_GPBR1_GPBR_VALUE1(value) ((SYS_GPBR1_GPBR_VALUE1_Msk & ((value) << SYS_GPBR1_GPBR_VALUE1_Pos)))
/* -------- SYS_GPBR2 : (GPBR Offset: 0x8) General Purpose Backup Register 2 -------- */
#define SYS_GPBR2_GPBR_VALUE2_Pos 0
#define SYS_GPBR2_GPBR_VALUE2_Msk (0xffffffffu << SYS_GPBR2_GPBR_VALUE2_Pos) /**< \brief (SYS_GPBR2) Value of GPBR x */
#define SYS_GPBR2_GPBR_VALUE2(value) ((SYS_GPBR2_GPBR_VALUE2_Msk & ((value) << SYS_GPBR2_GPBR_VALUE2_Pos)))
/* -------- SYS_GPBR3 : (GPBR Offset: 0xC) General Purpose Backup Register 3 -------- */
#define SYS_GPBR3_GPBR_VALUE3_Pos 0
#define SYS_GPBR3_GPBR_VALUE3_Msk (0xffffffffu << SYS_GPBR3_GPBR_VALUE3_Pos) /**< \brief (SYS_GPBR3) Value of GPBR x */
#define SYS_GPBR3_GPBR_VALUE3(value) ((SYS_GPBR3_GPBR_VALUE3_Msk & ((value) << SYS_GPBR3_GPBR_VALUE3_Pos)))

/*@}*/

/* ============================================================================= */
/**  SOFTWARE API DEFINITION FOR High Speed MultiMedia Card Interface */
/* ============================================================================= */
/** \addtogroup SAM9N12_HSMCI High Speed MultiMedia Card Interface */
/*@{*/

#ifndef __ASSEMBLY__
/** \brief Hsmci hardware registers */
typedef struct {
  WoReg HSMCI_CR;        /**< \brief (Hsmci Offset: 0x00) Control Register */
  RwReg HSMCI_MR;        /**< \brief (Hsmci Offset: 0x04) Mode Register */
  RwReg HSMCI_DTOR;      /**< \brief (Hsmci Offset: 0x08) Data Timeout Register */
  RwReg HSMCI_SDCR;      /**< \brief (Hsmci Offset: 0x0C) SD/SDIO Card Register */
  RwReg HSMCI_ARGR;      /**< \brief (Hsmci Offset: 0x10) Argument Register */
  WoReg HSMCI_CMDR;      /**< \brief (Hsmci Offset: 0x14) Command Register */
  RwReg HSMCI_BLKR;      /**< \brief (Hsmci Offset: 0x18) Block Register */
  RwReg HSMCI_CSTOR;     /**< \brief (Hsmci Offset: 0x1C) Completion Signal Timeout Register */
  RoReg HSMCI_RSPR[4];   /**< \brief (Hsmci Offset: 0x20) Response Register */
  RoReg HSMCI_RDR;       /**< \brief (Hsmci Offset: 0x30) Receive Data Register */
  WoReg HSMCI_TDR;       /**< \brief (Hsmci Offset: 0x34) Transmit Data Register */
  RoReg Reserved1[2];
  RoReg HSMCI_SR;        /**< \brief (Hsmci Offset: 0x40) Status Register */
  WoReg HSMCI_IER;       /**< \brief (Hsmci Offset: 0x44) Interrupt Enable Register */
  WoReg HSMCI_IDR;       /**< \brief (Hsmci Offset: 0x48) Interrupt Disable Register */
  RoReg HSMCI_IMR;       /**< \brief (Hsmci Offset: 0x4C) Interrupt Mask Register */
  RwReg HSMCI_DMA;       /**< \brief (Hsmci Offset: 0x50) DMA Configuration Register */
  RwReg HSMCI_CFG;       /**< \brief (Hsmci Offset: 0x54) Configuration Register */
  RoReg Reserved2[35];
  RwReg HSMCI_WPMR;      /**< \brief (Hsmci Offset: 0xE4) Write Protection Mode Register */
  RoReg HSMCI_WPSR;      /**< \brief (Hsmci Offset: 0xE8) Write Protection Status Register */
  RoReg Reserved3[69];
  RwReg HSMCI_FIFO[256]; /**< \brief (Hsmci Offset: 0x200) FIFO Memory Aperture0 */
} Hsmci;
#endif /* __ASSEMBLY__ */
/* -------- HSMCI_CR : (HSMCI Offset: 0x00) Control Register -------- */
#define HSMCI_CR_MCIEN (0x1u << 0) /**< \brief (HSMCI_CR) Multi-Media Interface Enable */
#define HSMCI_CR_MCIDIS (0x1u << 1) /**< \brief (HSMCI_CR) Multi-Media Interface Disable */
#define HSMCI_CR_PWSEN (0x1u << 2) /**< \brief (HSMCI_CR) Power Save Mode Enable */
#define HSMCI_CR_PWSDIS (0x1u << 3) /**< \brief (HSMCI_CR) Power Save Mode Disable */
#define HSMCI_CR_SWRST (0x1u << 7) /**< \brief (HSMCI_CR) Software Reset */
/* -------- HSMCI_MR : (HSMCI Offset: 0x04) Mode Register -------- */
#define HSMCI_MR_CLKDIV_Pos 0
#define HSMCI_MR_CLKDIV_Msk (0xffu << HSMCI_MR_CLKDIV_Pos) /**< \brief (HSMCI_MR) Clock Divider */
#define HSMCI_MR_CLKDIV(value) ((HSMCI_MR_CLKDIV_Msk & ((value) << HSMCI_MR_CLKDIV_Pos)))
#define HSMCI_MR_PWSDIV_Pos 8
#define HSMCI_MR_PWSDIV_Msk (0x7u << HSMCI_MR_PWSDIV_Pos) /**< \brief (HSMCI_MR) Power Saving Divider */
#define HSMCI_MR_PWSDIV(value) ((HSMCI_MR_PWSDIV_Msk & ((value) << HSMCI_MR_PWSDIV_Pos)))
#define HSMCI_MR_RDPROOF (0x1u << 11) /**< \brief (HSMCI_MR)  */
#define HSMCI_MR_WRPROOF (0x1u << 12) /**< \brief (HSMCI_MR)  */
#define HSMCI_MR_FBYTE (0x1u << 13) /**< \brief (HSMCI_MR) Force Byte Transfer */
#define HSMCI_MR_PADV (0x1u << 14) /**< \brief (HSMCI_MR) Padding Value */
#define HSMCI_MR_CLKODD (0x1u << 16) /**< \brief (HSMCI_MR) Clock divider is odd */
/* -------- HSMCI_DTOR : (HSMCI Offset: 0x08) Data Timeout Register -------- */
#define HSMCI_DTOR_DTOCYC_Pos 0
#define HSMCI_DTOR_DTOCYC_Msk (0xfu << HSMCI_DTOR_DTOCYC_Pos) /**< \brief (HSMCI_DTOR) Data Timeout Cycle Number */
#define HSMCI_DTOR_DTOCYC(value) ((HSMCI_DTOR_DTOCYC_Msk & ((value) << HSMCI_DTOR_DTOCYC_Pos)))
#define HSMCI_DTOR_DTOMUL_Pos 4
#define HSMCI_DTOR_DTOMUL_Msk (0x7u << HSMCI_DTOR_DTOMUL_Pos) /**< \brief (HSMCI_DTOR) Data Timeout Multiplier */
#define   HSMCI_DTOR_DTOMUL_1 (0x0u << 4) /**< \brief (HSMCI_DTOR) DTOCYC */
#define   HSMCI_DTOR_DTOMUL_16 (0x1u << 4) /**< \brief (HSMCI_DTOR) DTOCYC x 16 */
#define   HSMCI_DTOR_DTOMUL_128 (0x2u << 4) /**< \brief (HSMCI_DTOR) DTOCYC x 128 */
#define   HSMCI_DTOR_DTOMUL_256 (0x3u << 4) /**< \brief (HSMCI_DTOR) DTOCYC x 256 */
#define   HSMCI_DTOR_DTOMUL_1024 (0x4u << 4) /**< \brief (HSMCI_DTOR) DTOCYC x 1024 */
#define   HSMCI_DTOR_DTOMUL_4096 (0x5u << 4) /**< \brief (HSMCI_DTOR) DTOCYC x 4096 */
#define   HSMCI_DTOR_DTOMUL_65536 (0x6u << 4) /**< \brief (HSMCI_DTOR) DTOCYC x 65536 */
#define   HSMCI_DTOR_DTOMUL_1048576 (0x7u << 4) /**< \brief (HSMCI_DTOR) DTOCYC x 1048576 */
/* -------- HSMCI_SDCR : (HSMCI Offset: 0x0C) SD/SDIO Card Register -------- */
#define HSMCI_SDCR_SDCSEL_Pos 0
#define HSMCI_SDCR_SDCSEL_Msk (0x3u << HSMCI_SDCR_SDCSEL_Pos) /**< \brief (HSMCI_SDCR) SDCard/SDIO Slot */
#define   HSMCI_SDCR_SDCSEL_SLOTA (0x0u << 0) /**< \brief (HSMCI_SDCR) Slot A is selected. */
#define   HSMCI_SDCR_SDCSEL_SLOTB (0x1u << 0) /**< \brief (HSMCI_SDCR) - */
#define   HSMCI_SDCR_SDCSEL_SLOTC (0x2u << 0) /**< \brief (HSMCI_SDCR) - */
#define   HSMCI_SDCR_SDCSEL_SLOTD (0x3u << 0) /**< \brief (HSMCI_SDCR) - */
#define HSMCI_SDCR_SDCBUS_Pos 6
#define HSMCI_SDCR_SDCBUS_Msk (0x3u << HSMCI_SDCR_SDCBUS_Pos) /**< \brief (HSMCI_SDCR) SDCard/SDIO Bus Width */
#define   HSMCI_SDCR_SDCBUS_1 (0x0u << 6) /**< \brief (HSMCI_SDCR) 1 bit */
#define   HSMCI_SDCR_SDCBUS_4 (0x2u << 6) /**< \brief (HSMCI_SDCR) 4 bit */
#define   HSMCI_SDCR_SDCBUS_8 (0x3u << 6) /**< \brief (HSMCI_SDCR) 8 bit */
/* -------- HSMCI_ARGR : (HSMCI Offset: 0x10) Argument Register -------- */
#define HSMCI_ARGR_ARG_Pos 0
#define HSMCI_ARGR_ARG_Msk (0xffffffffu << HSMCI_ARGR_ARG_Pos) /**< \brief (HSMCI_ARGR) Command Argument */
#define HSMCI_ARGR_ARG(value) ((HSMCI_ARGR_ARG_Msk & ((value) << HSMCI_ARGR_ARG_Pos)))
/* -------- HSMCI_CMDR : (HSMCI Offset: 0x14) Command Register -------- */
#define HSMCI_CMDR_CMDNB_Pos 0
#define HSMCI_CMDR_CMDNB_Msk (0x3fu << HSMCI_CMDR_CMDNB_Pos) /**< \brief (HSMCI_CMDR) Command Number */
#define HSMCI_CMDR_CMDNB(value) ((HSMCI_CMDR_CMDNB_Msk & ((value) << HSMCI_CMDR_CMDNB_Pos)))
#define HSMCI_CMDR_RSPTYP_Pos 6
#define HSMCI_CMDR_RSPTYP_Msk (0x3u << HSMCI_CMDR_RSPTYP_Pos) /**< \brief (HSMCI_CMDR) Response Type */
#define   HSMCI_CMDR_RSPTYP_NORESP (0x0u << 6) /**< \brief (HSMCI_CMDR) No response. */
#define   HSMCI_CMDR_RSPTYP_48_BIT (0x1u << 6) /**< \brief (HSMCI_CMDR) 48-bit response. */
#define   HSMCI_CMDR_RSPTYP_136_BIT (0x2u << 6) /**< \brief (HSMCI_CMDR) 136-bit response. */
#define   HSMCI_CMDR_RSPTYP_R1B (0x3u << 6) /**< \brief (HSMCI_CMDR) R1b response type */
#define HSMCI_CMDR_SPCMD_Pos 8
#define HSMCI_CMDR_SPCMD_Msk (0x7u << HSMCI_CMDR_SPCMD_Pos) /**< \brief (HSMCI_CMDR) Special Command */
#define   HSMCI_CMDR_SPCMD_STD (0x0u << 8) /**< \brief (HSMCI_CMDR) Not a special CMD. */
#define   HSMCI_CMDR_SPCMD_INIT (0x1u << 8) /**< \brief (HSMCI_CMDR) Initialization CMD: 74 clock cycles for initialization sequence. */
#define   HSMCI_CMDR_SPCMD_SYNC (0x2u << 8) /**< \brief (HSMCI_CMDR) Synchronized CMD: Wait for the end of the current data block transfer before sending the pending command. */
#define   HSMCI_CMDR_SPCMD_CE_ATA (0x3u << 8) /**< \brief (HSMCI_CMDR) CE-ATA Completion Signal disable Command. The host cancels the ability for the device to return a command completion signal on the command line. */
#define   HSMCI_CMDR_SPCMD_IT_CMD (0x4u << 8) /**< \brief (HSMCI_CMDR) Interrupt command: Corresponds to the Interrupt Mode (CMD40). */
#define   HSMCI_CMDR_SPCMD_IT_RESP (0x5u << 8) /**< \brief (HSMCI_CMDR) Interrupt response: Corresponds to the Interrupt Mode (CMD40). */
#define   HSMCI_CMDR_SPCMD_BOR (0x6u << 8) /**< \brief (HSMCI_CMDR) Boot Operation Request. Start a boot operation mode, the host processor can read boot data from the MMC device directly. */
#define   HSMCI_CMDR_SPCMD_EBO (0x7u << 8) /**< \brief (HSMCI_CMDR) End Boot Operation. This command allows the host processor to terminate the boot operation mode. */
#define HSMCI_CMDR_OPDCMD (0x1u << 11) /**< \brief (HSMCI_CMDR) Open Drain Command */
#define   HSMCI_CMDR_OPDCMD_PUSHPULL (0x0u << 11) /**< \brief (HSMCI_CMDR) Push pull command. */
#define   HSMCI_CMDR_OPDCMD_OPENDRAIN (0x1u << 11) /**< \brief (HSMCI_CMDR) Open drain command. */
#define HSMCI_CMDR_MAXLAT (0x1u << 12) /**< \brief (HSMCI_CMDR) Max Latency for Command to Response */
#define   HSMCI_CMDR_MAXLAT_5 (0x0u << 12) /**< \brief (HSMCI_CMDR) 5-cycle max latency. */
#define   HSMCI_CMDR_MAXLAT_64 (0x1u << 12) /**< \brief (HSMCI_CMDR) 64-cycle max latency. */
#define HSMCI_CMDR_TRCMD_Pos 16
#define HSMCI_CMDR_TRCMD_Msk (0x3u << HSMCI_CMDR_TRCMD_Pos) /**< \brief (HSMCI_CMDR) Transfer Command */
#define   HSMCI_CMDR_TRCMD_NO_DATA (0x0u << 16) /**< \brief (HSMCI_CMDR) No data transfer */
#define   HSMCI_CMDR_TRCMD_START_DATA (0x1u << 16) /**< \brief (HSMCI_CMDR) Start data transfer */
#define   HSMCI_CMDR_TRCMD_STOP_DATA (0x2u << 16) /**< \brief (HSMCI_CMDR) Stop data transfer */
#define HSMCI_CMDR_TRDIR (0x1u << 18) /**< \brief (HSMCI_CMDR) Transfer Direction */
#define   HSMCI_CMDR_TRDIR_WRITE (0x0u << 18) /**< \brief (HSMCI_CMDR) Write. */
#define   HSMCI_CMDR_TRDIR_READ (0x1u << 18) /**< \brief (HSMCI_CMDR) Read. */
#define HSMCI_CMDR_TRTYP_Pos 19
#define HSMCI_CMDR_TRTYP_Msk (0x7u << HSMCI_CMDR_TRTYP_Pos) /**< \brief (HSMCI_CMDR) Transfer Type */
#define   HSMCI_CMDR_TRTYP_SINGLE (0x0u << 19) /**< \brief (HSMCI_CMDR) MMC/SDCard Single Block */
#define   HSMCI_CMDR_TRTYP_MULTIPLE (0x1u << 19) /**< \brief (HSMCI_CMDR) MMC/SDCard Multiple Block */
#define   HSMCI_CMDR_TRTYP_STREAM (0x2u << 19) /**< \brief (HSMCI_CMDR) MMC Stream */
#define   HSMCI_CMDR_TRTYP_BYTE (0x4u << 19) /**< \brief (HSMCI_CMDR) SDIO Byte */
#define   HSMCI_CMDR_TRTYP_BLOCK (0x5u << 19) /**< \brief (HSMCI_CMDR) SDIO Block */
#define HSMCI_CMDR_IOSPCMD_Pos 24
#define HSMCI_CMDR_IOSPCMD_Msk (0x3u << HSMCI_CMDR_IOSPCMD_Pos) /**< \brief (HSMCI_CMDR) SDIO Special Command */
#define   HSMCI_CMDR_IOSPCMD_STD (0x0u << 24) /**< \brief (HSMCI_CMDR) Not an SDIO Special Command */
#define   HSMCI_CMDR_IOSPCMD_SUSPEND (0x1u << 24) /**< \brief (HSMCI_CMDR) SDIO Suspend Command */
#define   HSMCI_CMDR_IOSPCMD_RESUME (0x2u << 24) /**< \brief (HSMCI_CMDR) SDIO Resume Command */
#define HSMCI_CMDR_ATACS (0x1u << 26) /**< \brief (HSMCI_CMDR) ATA with Command Completion Signal */
#define   HSMCI_CMDR_ATACS_NORMAL (0x0u << 26) /**< \brief (HSMCI_CMDR) Normal operation mode. */
#define   HSMCI_CMDR_ATACS_COMPLETION (0x1u << 26) /**< \brief (HSMCI_CMDR) This bit indicates that a completion signal is expected within a programmed amount of time (HSMCI_CSTOR). */
#define HSMCI_CMDR_BOOT_ACK (0x1u << 27) /**< \brief (HSMCI_CMDR) Boot Operation Acknowledge. */
/* -------- HSMCI_BLKR : (HSMCI Offset: 0x18) Block Register -------- */
#define HSMCI_BLKR_BCNT_Pos 0
#define HSMCI_BLKR_BCNT_Msk (0xffffu << HSMCI_BLKR_BCNT_Pos) /**< \brief (HSMCI_BLKR) MMC/SDIO Block Count - SDIO Byte Count */
#define   HSMCI_BLKR_BCNT_MULTIPLE (0x0u << 0) /**< \brief (HSMCI_BLKR) MMC/SDCARD Multiple BlockFrom 1 to 65635: Value 0 corresponds to an infinite block transfer. */
#define   HSMCI_BLKR_BCNT_BYTE (0x4u << 0) /**< \brief (HSMCI_BLKR) SDIO ByteFrom 1 to 512 bytes: Value 0 corresponds to a 512-byte transfer.Values from 0x200 to 0xFFFF are forbidden. */
#define   HSMCI_BLKR_BCNT_BLOCK (0x5u << 0) /**< \brief (HSMCI_BLKR) SDIO BlockFrom 1 to 511 blocks: Value 0 corresponds to an infinite block transfer.Values from 0x200 to 0xFFFF are forbidden. */
#define HSMCI_BLKR_BLKLEN_Pos 16
#define HSMCI_BLKR_BLKLEN_Msk (0xffffu << HSMCI_BLKR_BLKLEN_Pos) /**< \brief (HSMCI_BLKR) Data Block Length */
#define HSMCI_BLKR_BLKLEN(value) ((HSMCI_BLKR_BLKLEN_Msk & ((value) << HSMCI_BLKR_BLKLEN_Pos)))
/* -------- HSMCI_CSTOR : (HSMCI Offset: 0x1C) Completion Signal Timeout Register -------- */
#define HSMCI_CSTOR_CSTOCYC_Pos 0
#define HSMCI_CSTOR_CSTOCYC_Msk (0xfu << HSMCI_CSTOR_CSTOCYC_Pos) /**< \brief (HSMCI_CSTOR) Completion Signal Timeout Cycle Number */
#define HSMCI_CSTOR_CSTOCYC(value) ((HSMCI_CSTOR_CSTOCYC_Msk & ((value) << HSMCI_CSTOR_CSTOCYC_Pos)))
#define HSMCI_CSTOR_CSTOMUL_Pos 4
#define HSMCI_CSTOR_CSTOMUL_Msk (0x7u << HSMCI_CSTOR_CSTOMUL_Pos) /**< \brief (HSMCI_CSTOR) Completion Signal Timeout Multiplier */
#define   HSMCI_CSTOR_CSTOMUL_1 (0x0u << 4) /**< \brief (HSMCI_CSTOR) CSTOCYC x 1 */
#define   HSMCI_CSTOR_CSTOMUL_16 (0x1u << 4) /**< \brief (HSMCI_CSTOR) CSTOCYC x 16 */
#define   HSMCI_CSTOR_CSTOMUL_128 (0x2u << 4) /**< \brief (HSMCI_CSTOR) CSTOCYC x 128 */
#define   HSMCI_CSTOR_CSTOMUL_256 (0x3u << 4) /**< \brief (HSMCI_CSTOR) CSTOCYC x 256 */
#define   HSMCI_CSTOR_CSTOMUL_1024 (0x4u << 4) /**< \brief (HSMCI_CSTOR) CSTOCYC x 1024 */
#define   HSMCI_CSTOR_CSTOMUL_4096 (0x5u << 4) /**< \brief (HSMCI_CSTOR) CSTOCYC x 4096 */
#define   HSMCI_CSTOR_CSTOMUL_65536 (0x6u << 4) /**< \brief (HSMCI_CSTOR) CSTOCYC x 65536 */
#define   HSMCI_CSTOR_CSTOMUL_1048576 (0x7u << 4) /**< \brief (HSMCI_CSTOR) CSTOCYC x 1048576 */
/* -------- HSMCI_RSPR[4] : (HSMCI Offset: 0x20) Response Register -------- */
#define HSMCI_RSPR_RSP_Pos 0
#define HSMCI_RSPR_RSP_Msk (0xffffffffu << HSMCI_RSPR_RSP_Pos) /**< \brief (HSMCI_RSPR[4]) Response */
/* -------- HSMCI_RDR : (HSMCI Offset: 0x30) Receive Data Register -------- */
#define HSMCI_RDR_DATA_Pos 0
#define HSMCI_RDR_DATA_Msk (0xffffffffu << HSMCI_RDR_DATA_Pos) /**< \brief (HSMCI_RDR) Data to Read */
/* -------- HSMCI_TDR : (HSMCI Offset: 0x34) Transmit Data Register -------- */
#define HSMCI_TDR_DATA_Pos 0
#define HSMCI_TDR_DATA_Msk (0xffffffffu << HSMCI_TDR_DATA_Pos) /**< \brief (HSMCI_TDR) Data to Write */
#define HSMCI_TDR_DATA(value) ((HSMCI_TDR_DATA_Msk & ((value) << HSMCI_TDR_DATA_Pos)))
/* -------- HSMCI_SR : (HSMCI Offset: 0x40) Status Register -------- */
#define HSMCI_SR_CMDRDY (0x1u << 0) /**< \brief (HSMCI_SR) Command Ready */
#define HSMCI_SR_RXRDY (0x1u << 1) /**< \brief (HSMCI_SR) Receiver Ready */
#define HSMCI_SR_TXRDY (0x1u << 2) /**< \brief (HSMCI_SR) Transmit Ready */
#define HSMCI_SR_BLKE (0x1u << 3) /**< \brief (HSMCI_SR) Data Block Ended */
#define HSMCI_SR_DTIP (0x1u << 4) /**< \brief (HSMCI_SR) Data Transfer in Progress */
#define HSMCI_SR_NOTBUSY (0x1u << 5) /**< \brief (HSMCI_SR) HSMCI Not Busy */
#define HSMCI_SR_SDIOIRQA (0x1u << 8) /**< \brief (HSMCI_SR) SDIO Interrupt for Slot A */
#define HSMCI_SR_SDIOWAIT (0x1u << 12) /**< \brief (HSMCI_SR) SDIO Read Wait Operation Status */
#define HSMCI_SR_CSRCV (0x1u << 13) /**< \brief (HSMCI_SR) CE-ATA Completion Signal Received */
#define HSMCI_SR_RINDE (0x1u << 16) /**< \brief (HSMCI_SR) Response Index Error */
#define HSMCI_SR_RDIRE (0x1u << 17) /**< \brief (HSMCI_SR) Response Direction Error */
#define HSMCI_SR_RCRCE (0x1u << 18) /**< \brief (HSMCI_SR) Response CRC Error */
#define HSMCI_SR_RENDE (0x1u << 19) /**< \brief (HSMCI_SR) Response End Bit Error */
#define HSMCI_SR_RTOE (0x1u << 20) /**< \brief (HSMCI_SR) Response Time-out Error */
#define HSMCI_SR_DCRCE (0x1u << 21) /**< \brief (HSMCI_SR) Data CRC Error */
#define HSMCI_SR_DTOE (0x1u << 22) /**< \brief (HSMCI_SR) Data Time-out Error */
#define HSMCI_SR_CSTOE (0x1u << 23) /**< \brief (HSMCI_SR) Completion Signal Time-out Error */
#define HSMCI_SR_BLKOVRE (0x1u << 24) /**< \brief (HSMCI_SR) DMA Block Overrun Error */
#define HSMCI_SR_DMADONE (0x1u << 25) /**< \brief (HSMCI_SR) DMA Transfer done */
#define HSMCI_SR_FIFOEMPTY (0x1u << 26) /**< \brief (HSMCI_SR) FIFO empty flag */
#define HSMCI_SR_XFRDONE (0x1u << 27) /**< \brief (HSMCI_SR) Transfer Done flag */
#define HSMCI_SR_ACKRCV (0x1u << 28) /**< \brief (HSMCI_SR) Boot Operation Acknowledge Received */
#define HSMCI_SR_ACKRCVE (0x1u << 29) /**< \brief (HSMCI_SR) Boot Operation Acknowledge Error */
#define HSMCI_SR_OVRE (0x1u << 30) /**< \brief (HSMCI_SR) Overrun */
#define HSMCI_SR_UNRE (0x1u << 31) /**< \brief (HSMCI_SR) Underrun */
/* -------- HSMCI_IER : (HSMCI Offset: 0x44) Interrupt Enable Register -------- */
#define HSMCI_IER_CMDRDY (0x1u << 0) /**< \brief (HSMCI_IER) Command Ready Interrupt Enable */
#define HSMCI_IER_RXRDY (0x1u << 1) /**< \brief (HSMCI_IER) Receiver Ready Interrupt Enable */
#define HSMCI_IER_TXRDY (0x1u << 2) /**< \brief (HSMCI_IER) Transmit Ready Interrupt Enable */
#define HSMCI_IER_BLKE (0x1u << 3) /**< \brief (HSMCI_IER) Data Block Ended Interrupt Enable */
#define HSMCI_IER_DTIP (0x1u << 4) /**< \brief (HSMCI_IER) Data Transfer in Progress Interrupt Enable */
#define HSMCI_IER_NOTBUSY (0x1u << 5) /**< \brief (HSMCI_IER) Data Not Busy Interrupt Enable */
#define HSMCI_IER_SDIOIRQA (0x1u << 8) /**< \brief (HSMCI_IER) SDIO Interrupt for Slot A Interrupt Enable */
#define HSMCI_IER_SDIOWAIT (0x1u << 12) /**< \brief (HSMCI_IER) SDIO Read Wait Operation Status Interrupt Enable */
#define HSMCI_IER_CSRCV (0x1u << 13) /**< \brief (HSMCI_IER) Completion Signal Received Interrupt Enable */
#define HSMCI_IER_RINDE (0x1u << 16) /**< \brief (HSMCI_IER) Response Index Error Interrupt Enable */
#define HSMCI_IER_RDIRE (0x1u << 17) /**< \brief (HSMCI_IER) Response Direction Error Interrupt Enable */
#define HSMCI_IER_RCRCE (0x1u << 18) /**< \brief (HSMCI_IER) Response CRC Error Interrupt Enable */
#define HSMCI_IER_RENDE (0x1u << 19) /**< \brief (HSMCI_IER) Response End Bit Error Interrupt Enable */
#define HSMCI_IER_RTOE (0x1u << 20) /**< \brief (HSMCI_IER) Response Time-out Error Interrupt Enable */
#define HSMCI_IER_DCRCE (0x1u << 21) /**< \brief (HSMCI_IER) Data CRC Error Interrupt Enable */
#define HSMCI_IER_DTOE (0x1u << 22) /**< \brief (HSMCI_IER) Data Time-out Error Interrupt Enable */
#define HSMCI_IER_CSTOE (0x1u << 23) /**< \brief (HSMCI_IER) Completion Signal Timeout Error Interrupt Enable */
#define HSMCI_IER_BLKOVRE (0x1u << 24) /**< \brief (HSMCI_IER) DMA Block Overrun Error Interrupt Enable */
#define HSMCI_IER_DMADONE (0x1u << 25) /**< \brief (HSMCI_IER) DMA Transfer completed Interrupt Enable */
#define HSMCI_IER_FIFOEMPTY (0x1u << 26) /**< \brief (HSMCI_IER) FIFO empty Interrupt enable */
#define HSMCI_IER_XFRDONE (0x1u << 27) /**< \brief (HSMCI_IER) Transfer Done Interrupt enable */
#define HSMCI_IER_ACKRCV (0x1u << 28) /**< \brief (HSMCI_IER) Boot Acknowledge Interrupt Enable */
#define HSMCI_IER_ACKRCVE (0x1u << 29) /**< \brief (HSMCI_IER) Boot Acknowledge Error Interrupt Enable */
#define HSMCI_IER_OVRE (0x1u << 30) /**< \brief (HSMCI_IER) Overrun Interrupt Enable */
#define HSMCI_IER_UNRE (0x1u << 31) /**< \brief (HSMCI_IER) Underrun Interrupt Enable */
/* -------- HSMCI_IDR : (HSMCI Offset: 0x48) Interrupt Disable Register -------- */
#define HSMCI_IDR_CMDRDY (0x1u << 0) /**< \brief (HSMCI_IDR) Command Ready Interrupt Disable */
#define HSMCI_IDR_RXRDY (0x1u << 1) /**< \brief (HSMCI_IDR) Receiver Ready Interrupt Disable */
#define HSMCI_IDR_TXRDY (0x1u << 2) /**< \brief (HSMCI_IDR) Transmit Ready Interrupt Disable */
#define HSMCI_IDR_BLKE (0x1u << 3) /**< \brief (HSMCI_IDR) Data Block Ended Interrupt Disable */
#define HSMCI_IDR_DTIP (0x1u << 4) /**< \brief (HSMCI_IDR) Data Transfer in Progress Interrupt Disable */
#define HSMCI_IDR_NOTBUSY (0x1u << 5) /**< \brief (HSMCI_IDR) Data Not Busy Interrupt Disable */
#define HSMCI_IDR_SDIOIRQA (0x1u << 8) /**< \brief (HSMCI_IDR) SDIO Interrupt for Slot A Interrupt Disable */
#define HSMCI_IDR_SDIOWAIT (0x1u << 12) /**< \brief (HSMCI_IDR) SDIO Read Wait Operation Status Interrupt Disable */
#define HSMCI_IDR_CSRCV (0x1u << 13) /**< \brief (HSMCI_IDR) Completion Signal received interrupt Disable */
#define HSMCI_IDR_RINDE (0x1u << 16) /**< \brief (HSMCI_IDR) Response Index Error Interrupt Disable */
#define HSMCI_IDR_RDIRE (0x1u << 17) /**< \brief (HSMCI_IDR) Response Direction Error Interrupt Disable */
#define HSMCI_IDR_RCRCE (0x1u << 18) /**< \brief (HSMCI_IDR) Response CRC Error Interrupt Disable */
#define HSMCI_IDR_RENDE (0x1u << 19) /**< \brief (HSMCI_IDR) Response End Bit Error Interrupt Disable */
#define HSMCI_IDR_RTOE (0x1u << 20) /**< \brief (HSMCI_IDR) Response Time-out Error Interrupt Disable */
#define HSMCI_IDR_DCRCE (0x1u << 21) /**< \brief (HSMCI_IDR) Data CRC Error Interrupt Disable */
#define HSMCI_IDR_DTOE (0x1u << 22) /**< \brief (HSMCI_IDR) Data Time-out Error Interrupt Disable */
#define HSMCI_IDR_CSTOE (0x1u << 23) /**< \brief (HSMCI_IDR) Completion Signal Time out Error Interrupt Disable */
#define HSMCI_IDR_BLKOVRE (0x1u << 24) /**< \brief (HSMCI_IDR) DMA Block Overrun Error Interrupt Disable */
#define HSMCI_IDR_DMADONE (0x1u << 25) /**< \brief (HSMCI_IDR) DMA Transfer completed Interrupt Disable */
#define HSMCI_IDR_FIFOEMPTY (0x1u << 26) /**< \brief (HSMCI_IDR) FIFO empty Interrupt Disable */
#define HSMCI_IDR_XFRDONE (0x1u << 27) /**< \brief (HSMCI_IDR) Transfer Done Interrupt Disable */
#define HSMCI_IDR_ACKRCV (0x1u << 28) /**< \brief (HSMCI_IDR) Boot Acknowledge Interrupt Disable */
#define HSMCI_IDR_ACKRCVE (0x1u << 29) /**< \brief (HSMCI_IDR) Boot Acknowledge Error Interrupt Disable */
#define HSMCI_IDR_OVRE (0x1u << 30) /**< \brief (HSMCI_IDR) Overrun Interrupt Disable */
#define HSMCI_IDR_UNRE (0x1u << 31) /**< \brief (HSMCI_IDR) Underrun Interrupt Disable */
/* -------- HSMCI_IMR : (HSMCI Offset: 0x4C) Interrupt Mask Register -------- */
#define HSMCI_IMR_CMDRDY (0x1u << 0) /**< \brief (HSMCI_IMR) Command Ready Interrupt Mask */
#define HSMCI_IMR_RXRDY (0x1u << 1) /**< \brief (HSMCI_IMR) Receiver Ready Interrupt Mask */
#define HSMCI_IMR_TXRDY (0x1u << 2) /**< \brief (HSMCI_IMR) Transmit Ready Interrupt Mask */
#define HSMCI_IMR_BLKE (0x1u << 3) /**< \brief (HSMCI_IMR) Data Block Ended Interrupt Mask */
#define HSMCI_IMR_DTIP (0x1u << 4) /**< \brief (HSMCI_IMR) Data Transfer in Progress Interrupt Mask */
#define HSMCI_IMR_NOTBUSY (0x1u << 5) /**< \brief (HSMCI_IMR) Data Not Busy Interrupt Mask */
#define HSMCI_IMR_SDIOIRQA (0x1u << 8) /**< \brief (HSMCI_IMR) SDIO Interrupt for Slot A Interrupt Mask */
#define HSMCI_IMR_SDIOWAIT (0x1u << 12) /**< \brief (HSMCI_IMR) SDIO Read Wait Operation Status Interrupt Mask */
#define HSMCI_IMR_CSRCV (0x1u << 13) /**< \brief (HSMCI_IMR) Completion Signal Received Interrupt Mask */
#define HSMCI_IMR_RINDE (0x1u << 16) /**< \brief (HSMCI_IMR) Response Index Error Interrupt Mask */
#define HSMCI_IMR_RDIRE (0x1u << 17) /**< \brief (HSMCI_IMR) Response Direction Error Interrupt Mask */
#define HSMCI_IMR_RCRCE (0x1u << 18) /**< \brief (HSMCI_IMR) Response CRC Error Interrupt Mask */
#define HSMCI_IMR_RENDE (0x1u << 19) /**< \brief (HSMCI_IMR) Response End Bit Error Interrupt Mask */
#define HSMCI_IMR_RTOE (0x1u << 20) /**< \brief (HSMCI_IMR) Response Time-out Error Interrupt Mask */
#define HSMCI_IMR_DCRCE (0x1u << 21) /**< \brief (HSMCI_IMR) Data CRC Error Interrupt Mask */
#define HSMCI_IMR_DTOE (0x1u << 22) /**< \brief (HSMCI_IMR) Data Time-out Error Interrupt Mask */
#define HSMCI_IMR_CSTOE (0x1u << 23) /**< \brief (HSMCI_IMR) Completion Signal Time-out Error Interrupt Mask */
#define HSMCI_IMR_BLKOVRE (0x1u << 24) /**< \brief (HSMCI_IMR) DMA Block Overrun Error Interrupt Mask */
#define HSMCI_IMR_DMADONE (0x1u << 25) /**< \brief (HSMCI_IMR) DMA Transfer Completed Interrupt Mask */
#define HSMCI_IMR_FIFOEMPTY (0x1u << 26) /**< \brief (HSMCI_IMR) FIFO Empty Interrupt Mask */
#define HSMCI_IMR_XFRDONE (0x1u << 27) /**< \brief (HSMCI_IMR) Transfer Done Interrupt Mask */
#define HSMCI_IMR_ACKRCV (0x1u << 28) /**< \brief (HSMCI_IMR) Boot Operation Acknowledge Received Interrupt Mask */
#define HSMCI_IMR_ACKRCVE (0x1u << 29) /**< \brief (HSMCI_IMR) Boot Operation Acknowledge Error Interrupt Mask */
#define HSMCI_IMR_OVRE (0x1u << 30) /**< \brief (HSMCI_IMR) Overrun Interrupt Mask */
#define HSMCI_IMR_UNRE (0x1u << 31) /**< \brief (HSMCI_IMR) Underrun Interrupt Mask */
/* -------- HSMCI_DMA : (HSMCI Offset: 0x50) DMA Configuration Register -------- */
#define HSMCI_DMA_OFFSET_Pos 0
#define HSMCI_DMA_OFFSET_Msk (0x3u << HSMCI_DMA_OFFSET_Pos) /**< \brief (HSMCI_DMA) DMA Write Buffer Offset */
#define HSMCI_DMA_OFFSET(value) ((HSMCI_DMA_OFFSET_Msk & ((value) << HSMCI_DMA_OFFSET_Pos)))
#define HSMCI_DMA_CHKSIZE_Pos 4
#define HSMCI_DMA_CHKSIZE_Msk (0x7u << HSMCI_DMA_CHKSIZE_Pos) /**< \brief (HSMCI_DMA) DMA Channel Read and Write Chunk Size */
#define   HSMCI_DMA_CHKSIZE_1 (0x0u << 4) /**< \brief (HSMCI_DMA) 1 data available */
#define   HSMCI_DMA_CHKSIZE_4 (0x1u << 4) /**< \brief (HSMCI_DMA) 4 data available */
#define   HSMCI_DMA_CHKSIZE_8 (0x2u << 4) /**< \brief (HSMCI_DMA) 8 data available */
#define   HSMCI_DMA_CHKSIZE_16 (0x3u << 4) /**< \brief (HSMCI_DMA) 16 data available */
#define   HSMCI_DMA_CHKSIZE_32 (0x4u << 4) /**< \brief (HSMCI_DMA) 32 data available */
#define HSMCI_DMA_DMAEN (0x1u << 8) /**< \brief (HSMCI_DMA) DMA Hardware Handshaking Enable */
#define HSMCI_DMA_ROPT (0x1u << 12) /**< \brief (HSMCI_DMA) Read Optimization with padding */
/* -------- HSMCI_CFG : (HSMCI Offset: 0x54) Configuration Register -------- */
#define HSMCI_CFG_FIFOMODE (0x1u << 0) /**< \brief (HSMCI_CFG) HSMCI Internal FIFO control mode */
#define HSMCI_CFG_FERRCTRL (0x1u << 4) /**< \brief (HSMCI_CFG) Flow Error flag reset control mode */
#define HSMCI_CFG_HSMODE (0x1u << 8) /**< \brief (HSMCI_CFG) High Speed Mode */
#define HSMCI_CFG_LSYNC (0x1u << 12) /**< \brief (HSMCI_CFG) Synchronize on the last block */
/* -------- HSMCI_WPMR : (HSMCI Offset: 0xE4) Write Protection Mode Register -------- */
#define HSMCI_WPMR_WP_EN (0x1u << 0) /**< \brief (HSMCI_WPMR) Write Protection Enable */
#define HSMCI_WPMR_WP_KEY_Pos 8
#define HSMCI_WPMR_WP_KEY_Msk (0xffffffu << HSMCI_WPMR_WP_KEY_Pos) /**< \brief (HSMCI_WPMR) Write Protection Key password */
#define HSMCI_WPMR_WP_KEY(value) ((HSMCI_WPMR_WP_KEY_Msk & ((value) << HSMCI_WPMR_WP_KEY_Pos)))
/* -------- HSMCI_WPSR : (HSMCI Offset: 0xE8) Write Protection Status Register -------- */
#define HSMCI_WPSR_WP_VS_Pos 0
#define HSMCI_WPSR_WP_VS_Msk (0xfu << HSMCI_WPSR_WP_VS_Pos) /**< \brief (HSMCI_WPSR) Write Protection Violation Status */
#define   HSMCI_WPSR_WP_VS_NONE (0x0u << 0) /**< \brief (HSMCI_WPSR) No Write Protection Violation occurred since the last read of this register (WP_SR) */
#define   HSMCI_WPSR_WP_VS_WRITE (0x1u << 0) /**< \brief (HSMCI_WPSR) Write Protection detected unauthorized attempt to write a control register had occurred (since the last read.) */
#define   HSMCI_WPSR_WP_VS_RESET (0x2u << 0) /**< \brief (HSMCI_WPSR) Software reset had been performed while Write Protection was enabled (since the last read). */
#define   HSMCI_WPSR_WP_VS_BOTH (0x3u << 0) /**< \brief (HSMCI_WPSR) Both Write Protection violation and software reset with Write Protection enabled have occurred since the last read. */
#define HSMCI_WPSR_WP_VSRC_Pos 8
#define HSMCI_WPSR_WP_VSRC_Msk (0xffffu << HSMCI_WPSR_WP_VSRC_Pos) /**< \brief (HSMCI_WPSR) Write Protection Violation SouRCe */
/* -------- HSMCI_FIFO[256] : (HSMCI Offset: 0x200) FIFO Memory Aperture0 -------- */
#define HSMCI_FIFO_DATA_Pos 0
#define HSMCI_FIFO_DATA_Msk (0xffffffffu << HSMCI_FIFO_DATA_Pos) /**< \brief (HSMCI_FIFO[256]) Data to Read or Data to Write */
#define HSMCI_FIFO_DATA(value) ((HSMCI_FIFO_DATA_Msk & ((value) << HSMCI_FIFO_DATA_Pos)))

/*@}*/

/* ============================================================================= */
/**  SOFTWARE API DEFINITION FOR AHB Bus Matrix */
/* ============================================================================= */
/** \addtogroup SAM9N12_MATRIX AHB Bus Matrix */
/*@{*/

#ifndef __ASSEMBLY__
/** \brief Matrix hardware registers */
typedef struct {
  RwReg MATRIX_MCFG[6]; /**< \brief (Matrix Offset: 0x0000) Master Configuration Register */
  RoReg Reserved1[10];
  RwReg MATRIX_SCFG[5]; /**< \brief (Matrix Offset: 0x0040) Slave Configuration Register */
  RoReg Reserved2[11];
  RwReg MATRIX_PRAS0;   /**< \brief (Matrix Offset: 0x0080) Priority Register A for Slave 0 */
  RoReg Reserved3[1];
  RwReg MATRIX_PRAS1;   /**< \brief (Matrix Offset: 0x0088) Priority Register A for Slave 1 */
  RoReg Reserved4[1];
  RwReg MATRIX_PRAS2;   /**< \brief (Matrix Offset: 0x0090) Priority Register A for Slave 2 */
  RoReg Reserved5[1];
  RwReg MATRIX_PRAS3;   /**< \brief (Matrix Offset: 0x0098) Priority Register A for Slave 3 */
  RoReg Reserved6[1];
  RwReg MATRIX_PRAS4;   /**< \brief (Matrix Offset: 0x00A0) Priority Register A for Slave 4 */
  RoReg Reserved7[1];
  RoReg Reserved8[22];
  RwReg MATRIX_MRCR;    /**< \brief (Matrix Offset: 0x0100) Master Remap Control Register */
  RoReg Reserved9[56];
  RwReg MATRIX_WPMR;    /**< \brief (Matrix Offset: 0x01E4) Write Protect Mode Register */
  RoReg MATRIX_WPSR;    /**< \brief (Matrix Offset: 0x01E8) Write Protect Status Register */
} Matrix;
#endif /* __ASSEMBLY__ */
/* -------- MATRIX_MCFG[6] : (MATRIX Offset: 0x0000) Master Configuration Register -------- */
#define MATRIX_MCFG_ULBT_Pos 0
#define MATRIX_MCFG_ULBT_Msk (0x7u << MATRIX_MCFG_ULBT_Pos) /**< \brief (MATRIX_MCFG[6]) Undefined Length Burst Type */
#define MATRIX_MCFG_ULBT(value) ((MATRIX_MCFG_ULBT_Msk & ((value) << MATRIX_MCFG_ULBT_Pos)))
/* -------- MATRIX_SCFG[5] : (MATRIX Offset: 0x0040) Slave Configuration Register -------- */
#define MATRIX_SCFG_SLOT_CYCLE_Pos 0
#define MATRIX_SCFG_SLOT_CYCLE_Msk (0x1ffu << MATRIX_SCFG_SLOT_CYCLE_Pos) /**< \brief (MATRIX_SCFG[5]) Maximum Bus Grant Duration for Masters */
#define MATRIX_SCFG_SLOT_CYCLE(value) ((MATRIX_SCFG_SLOT_CYCLE_Msk & ((value) << MATRIX_SCFG_SLOT_CYCLE_Pos)))
#define MATRIX_SCFG_DEFMSTR_TYPE_Pos 16
#define MATRIX_SCFG_DEFMSTR_TYPE_Msk (0x3u << MATRIX_SCFG_DEFMSTR_TYPE_Pos) /**< \brief (MATRIX_SCFG[5]) Default Master Type */
#define MATRIX_SCFG_DEFMSTR_TYPE(value) ((MATRIX_SCFG_DEFMSTR_TYPE_Msk & ((value) << MATRIX_SCFG_DEFMSTR_TYPE_Pos)))
#define MATRIX_SCFG_FIXED_DEFMSTR_Pos 18
#define MATRIX_SCFG_FIXED_DEFMSTR_Msk (0xfu << MATRIX_SCFG_FIXED_DEFMSTR_Pos) /**< \brief (MATRIX_SCFG[5]) Fixed Default Master */
#define MATRIX_SCFG_FIXED_DEFMSTR(value) ((MATRIX_SCFG_FIXED_DEFMSTR_Msk & ((value) << MATRIX_SCFG_FIXED_DEFMSTR_Pos)))
/* -------- MATRIX_PRAS0 : (MATRIX Offset: 0x0080) Priority Register A for Slave 0 -------- */
#define MATRIX_PRAS0_M0PR_Pos 0
#define MATRIX_PRAS0_M0PR_Msk (0x3u << MATRIX_PRAS0_M0PR_Pos) /**< \brief (MATRIX_PRAS0) Master 0 Priority */
#define MATRIX_PRAS0_M0PR(value) ((MATRIX_PRAS0_M0PR_Msk & ((value) << MATRIX_PRAS0_M0PR_Pos)))
#define MATRIX_PRAS0_M1PR_Pos 4
#define MATRIX_PRAS0_M1PR_Msk (0x3u << MATRIX_PRAS0_M1PR_Pos) /**< \brief (MATRIX_PRAS0) Master 1 Priority */
#define MATRIX_PRAS0_M1PR(value) ((MATRIX_PRAS0_M1PR_Msk & ((value) << MATRIX_PRAS0_M1PR_Pos)))
#define MATRIX_PRAS0_M2PR_Pos 8
#define MATRIX_PRAS0_M2PR_Msk (0x3u << MATRIX_PRAS0_M2PR_Pos) /**< \brief (MATRIX_PRAS0) Master 2 Priority */
#define MATRIX_PRAS0_M2PR(value) ((MATRIX_PRAS0_M2PR_Msk & ((value) << MATRIX_PRAS0_M2PR_Pos)))
#define MATRIX_PRAS0_M3PR_Pos 12
#define MATRIX_PRAS0_M3PR_Msk (0x3u << MATRIX_PRAS0_M3PR_Pos) /**< \brief (MATRIX_PRAS0) Master 3 Priority */
#define MATRIX_PRAS0_M3PR(value) ((MATRIX_PRAS0_M3PR_Msk & ((value) << MATRIX_PRAS0_M3PR_Pos)))
#define MATRIX_PRAS0_M4PR_Pos 16
#define MATRIX_PRAS0_M4PR_Msk (0x3u << MATRIX_PRAS0_M4PR_Pos) /**< \brief (MATRIX_PRAS0) Master 4 Priority */
#define MATRIX_PRAS0_M4PR(value) ((MATRIX_PRAS0_M4PR_Msk & ((value) << MATRIX_PRAS0_M4PR_Pos)))
#define MATRIX_PRAS0_M5PR_Pos 20
#define MATRIX_PRAS0_M5PR_Msk (0x3u << MATRIX_PRAS0_M5PR_Pos) /**< \brief (MATRIX_PRAS0) Master 5 Priority */
#define MATRIX_PRAS0_M5PR(value) ((MATRIX_PRAS0_M5PR_Msk & ((value) << MATRIX_PRAS0_M5PR_Pos)))
/* -------- MATRIX_PRAS1 : (MATRIX Offset: 0x0088) Priority Register A for Slave 1 -------- */
#define MATRIX_PRAS1_M0PR_Pos 0
#define MATRIX_PRAS1_M0PR_Msk (0x3u << MATRIX_PRAS1_M0PR_Pos) /**< \brief (MATRIX_PRAS1) Master 0 Priority */
#define MATRIX_PRAS1_M0PR(value) ((MATRIX_PRAS1_M0PR_Msk & ((value) << MATRIX_PRAS1_M0PR_Pos)))
#define MATRIX_PRAS1_M1PR_Pos 4
#define MATRIX_PRAS1_M1PR_Msk (0x3u << MATRIX_PRAS1_M1PR_Pos) /**< \brief (MATRIX_PRAS1) Master 1 Priority */
#define MATRIX_PRAS1_M1PR(value) ((MATRIX_PRAS1_M1PR_Msk & ((value) << MATRIX_PRAS1_M1PR_Pos)))
#define MATRIX_PRAS1_M2PR_Pos 8
#define MATRIX_PRAS1_M2PR_Msk (0x3u << MATRIX_PRAS1_M2PR_Pos) /**< \brief (MATRIX_PRAS1) Master 2 Priority */
#define MATRIX_PRAS1_M2PR(value) ((MATRIX_PRAS1_M2PR_Msk & ((value) << MATRIX_PRAS1_M2PR_Pos)))
#define MATRIX_PRAS1_M3PR_Pos 12
#define MATRIX_PRAS1_M3PR_Msk (0x3u << MATRIX_PRAS1_M3PR_Pos) /**< \brief (MATRIX_PRAS1) Master 3 Priority */
#define MATRIX_PRAS1_M3PR(value) ((MATRIX_PRAS1_M3PR_Msk & ((value) << MATRIX_PRAS1_M3PR_Pos)))
#define MATRIX_PRAS1_M4PR_Pos 16
#define MATRIX_PRAS1_M4PR_Msk (0x3u << MATRIX_PRAS1_M4PR_Pos) /**< \brief (MATRIX_PRAS1) Master 4 Priority */
#define MATRIX_PRAS1_M4PR(value) ((MATRIX_PRAS1_M4PR_Msk & ((value) << MATRIX_PRAS1_M4PR_Pos)))
#define MATRIX_PRAS1_M5PR_Pos 20
#define MATRIX_PRAS1_M5PR_Msk (0x3u << MATRIX_PRAS1_M5PR_Pos) /**< \brief (MATRIX_PRAS1) Master 5 Priority */
#define MATRIX_PRAS1_M5PR(value) ((MATRIX_PRAS1_M5PR_Msk & ((value) << MATRIX_PRAS1_M5PR_Pos)))
/* -------- MATRIX_PRAS2 : (MATRIX Offset: 0x0090) Priority Register A for Slave 2 -------- */
#define MATRIX_PRAS2_M0PR_Pos 0
#define MATRIX_PRAS2_M0PR_Msk (0x3u << MATRIX_PRAS2_M0PR_Pos) /**< \brief (MATRIX_PRAS2) Master 0 Priority */
#define MATRIX_PRAS2_M0PR(value) ((MATRIX_PRAS2_M0PR_Msk & ((value) << MATRIX_PRAS2_M0PR_Pos)))
#define MATRIX_PRAS2_M1PR_Pos 4
#define MATRIX_PRAS2_M1PR_Msk (0x3u << MATRIX_PRAS2_M1PR_Pos) /**< \brief (MATRIX_PRAS2) Master 1 Priority */
#define MATRIX_PRAS2_M1PR(value) ((MATRIX_PRAS2_M1PR_Msk & ((value) << MATRIX_PRAS2_M1PR_Pos)))
#define MATRIX_PRAS2_M2PR_Pos 8
#define MATRIX_PRAS2_M2PR_Msk (0x3u << MATRIX_PRAS2_M2PR_Pos) /**< \brief (MATRIX_PRAS2) Master 2 Priority */
#define MATRIX_PRAS2_M2PR(value) ((MATRIX_PRAS2_M2PR_Msk & ((value) << MATRIX_PRAS2_M2PR_Pos)))
#define MATRIX_PRAS2_M3PR_Pos 12
#define MATRIX_PRAS2_M3PR_Msk (0x3u << MATRIX_PRAS2_M3PR_Pos) /**< \brief (MATRIX_PRAS2) Master 3 Priority */
#define MATRIX_PRAS2_M3PR(value) ((MATRIX_PRAS2_M3PR_Msk & ((value) << MATRIX_PRAS2_M3PR_Pos)))
#define MATRIX_PRAS2_M4PR_Pos 16
#define MATRIX_PRAS2_M4PR_Msk (0x3u << MATRIX_PRAS2_M4PR_Pos) /**< \brief (MATRIX_PRAS2) Master 4 Priority */
#define MATRIX_PRAS2_M4PR(value) ((MATRIX_PRAS2_M4PR_Msk & ((value) << MATRIX_PRAS2_M4PR_Pos)))
#define MATRIX_PRAS2_M5PR_Pos 20
#define MATRIX_PRAS2_M5PR_Msk (0x3u << MATRIX_PRAS2_M5PR_Pos) /**< \brief (MATRIX_PRAS2) Master 5 Priority */
#define MATRIX_PRAS2_M5PR(value) ((MATRIX_PRAS2_M5PR_Msk & ((value) << MATRIX_PRAS2_M5PR_Pos)))
/* -------- MATRIX_PRAS3 : (MATRIX Offset: 0x0098) Priority Register A for Slave 3 -------- */
#define MATRIX_PRAS3_M0PR_Pos 0
#define MATRIX_PRAS3_M0PR_Msk (0x3u << MATRIX_PRAS3_M0PR_Pos) /**< \brief (MATRIX_PRAS3) Master 0 Priority */
#define MATRIX_PRAS3_M0PR(value) ((MATRIX_PRAS3_M0PR_Msk & ((value) << MATRIX_PRAS3_M0PR_Pos)))
#define MATRIX_PRAS3_M1PR_Pos 4
#define MATRIX_PRAS3_M1PR_Msk (0x3u << MATRIX_PRAS3_M1PR_Pos) /**< \brief (MATRIX_PRAS3) Master 1 Priority */
#define MATRIX_PRAS3_M1PR(value) ((MATRIX_PRAS3_M1PR_Msk & ((value) << MATRIX_PRAS3_M1PR_Pos)))
#define MATRIX_PRAS3_M2PR_Pos 8
#define MATRIX_PRAS3_M2PR_Msk (0x3u << MATRIX_PRAS3_M2PR_Pos) /**< \brief (MATRIX_PRAS3) Master 2 Priority */
#define MATRIX_PRAS3_M2PR(value) ((MATRIX_PRAS3_M2PR_Msk & ((value) << MATRIX_PRAS3_M2PR_Pos)))
#define MATRIX_PRAS3_M3PR_Pos 12
#define MATRIX_PRAS3_M3PR_Msk (0x3u << MATRIX_PRAS3_M3PR_Pos) /**< \brief (MATRIX_PRAS3) Master 3 Priority */
#define MATRIX_PRAS3_M3PR(value) ((MATRIX_PRAS3_M3PR_Msk & ((value) << MATRIX_PRAS3_M3PR_Pos)))
#define MATRIX_PRAS3_M4PR_Pos 16
#define MATRIX_PRAS3_M4PR_Msk (0x3u << MATRIX_PRAS3_M4PR_Pos) /**< \brief (MATRIX_PRAS3) Master 4 Priority */
#define MATRIX_PRAS3_M4PR(value) ((MATRIX_PRAS3_M4PR_Msk & ((value) << MATRIX_PRAS3_M4PR_Pos)))
#define MATRIX_PRAS3_M5PR_Pos 20
#define MATRIX_PRAS3_M5PR_Msk (0x3u << MATRIX_PRAS3_M5PR_Pos) /**< \brief (MATRIX_PRAS3) Master 5 Priority */
#define MATRIX_PRAS3_M5PR(value) ((MATRIX_PRAS3_M5PR_Msk & ((value) << MATRIX_PRAS3_M5PR_Pos)))
/* -------- MATRIX_PRAS4 : (MATRIX Offset: 0x00A0) Priority Register A for Slave 4 -------- */
#define MATRIX_PRAS4_M0PR_Pos 0
#define MATRIX_PRAS4_M0PR_Msk (0x3u << MATRIX_PRAS4_M0PR_Pos) /**< \brief (MATRIX_PRAS4) Master 0 Priority */
#define MATRIX_PRAS4_M0PR(value) ((MATRIX_PRAS4_M0PR_Msk & ((value) << MATRIX_PRAS4_M0PR_Pos)))
#define MATRIX_PRAS4_M1PR_Pos 4
#define MATRIX_PRAS4_M1PR_Msk (0x3u << MATRIX_PRAS4_M1PR_Pos) /**< \brief (MATRIX_PRAS4) Master 1 Priority */
#define MATRIX_PRAS4_M1PR(value) ((MATRIX_PRAS4_M1PR_Msk & ((value) << MATRIX_PRAS4_M1PR_Pos)))
#define MATRIX_PRAS4_M2PR_Pos 8
#define MATRIX_PRAS4_M2PR_Msk (0x3u << MATRIX_PRAS4_M2PR_Pos) /**< \brief (MATRIX_PRAS4) Master 2 Priority */
#define MATRIX_PRAS4_M2PR(value) ((MATRIX_PRAS4_M2PR_Msk & ((value) << MATRIX_PRAS4_M2PR_Pos)))
#define MATRIX_PRAS4_M3PR_Pos 12
#define MATRIX_PRAS4_M3PR_Msk (0x3u << MATRIX_PRAS4_M3PR_Pos) /**< \brief (MATRIX_PRAS4) Master 3 Priority */
#define MATRIX_PRAS4_M3PR(value) ((MATRIX_PRAS4_M3PR_Msk & ((value) << MATRIX_PRAS4_M3PR_Pos)))
#define MATRIX_PRAS4_M4PR_Pos 16
#define MATRIX_PRAS4_M4PR_Msk (0x3u << MATRIX_PRAS4_M4PR_Pos) /**< \brief (MATRIX_PRAS4) Master 4 Priority */
#define MATRIX_PRAS4_M4PR(value) ((MATRIX_PRAS4_M4PR_Msk & ((value) << MATRIX_PRAS4_M4PR_Pos)))
#define MATRIX_PRAS4_M5PR_Pos 20
#define MATRIX_PRAS4_M5PR_Msk (0x3u << MATRIX_PRAS4_M5PR_Pos) /**< \brief (MATRIX_PRAS4) Master 5 Priority */
#define MATRIX_PRAS4_M5PR(value) ((MATRIX_PRAS4_M5PR_Msk & ((value) << MATRIX_PRAS4_M5PR_Pos)))
/* -------- MATRIX_MRCR : (MATRIX Offset: 0x0100) Master Remap Control Register -------- */
#define MATRIX_MRCR_RCB0 (0x1u << 0) /**< \brief (MATRIX_MRCR) Remap Command Bit for Master 0 */
#define MATRIX_MRCR_RCB1 (0x1u << 1) /**< \brief (MATRIX_MRCR) Remap Command Bit for Master 1 */
#define MATRIX_MRCR_RCB2 (0x1u << 2) /**< \brief (MATRIX_MRCR) Remap Command Bit for Master 2 */
#define MATRIX_MRCR_RCB3 (0x1u << 3) /**< \brief (MATRIX_MRCR) Remap Command Bit for Master 3 */
#define MATRIX_MRCR_RCB4 (0x1u << 4) /**< \brief (MATRIX_MRCR) Remap Command Bit for Master 4 */
#define MATRIX_MRCR_RCB5 (0x1u << 5) /**< \brief (MATRIX_MRCR) Remap Command Bit for Master 5 */
/* -------- MATRIX_WPMR : (MATRIX Offset: 0x01E4) Write Protect Mode Register -------- */
#define MATRIX_WPMR_WPEN (0x1u << 0) /**< \brief (MATRIX_WPMR) Write Protect ENable */
#define MATRIX_WPMR_WPKEY_Pos 8
#define MATRIX_WPMR_WPKEY_Msk (0xffffffu << MATRIX_WPMR_WPKEY_Pos) /**< \brief (MATRIX_WPMR) Write Protect KEY (Write-only) */
#define MATRIX_WPMR_WPKEY(value) ((MATRIX_WPMR_WPKEY_Msk & ((value) << MATRIX_WPMR_WPKEY_Pos)))
/* -------- MATRIX_WPSR : (MATRIX Offset: 0x01E8) Write Protect Status Register -------- */
#define MATRIX_WPSR_WPVS (0x1u << 0) /**< \brief (MATRIX_WPSR) Write Protect Violation Status */
#define MATRIX_WPSR_WPVSRC_Pos 8
#define MATRIX_WPSR_WPVSRC_Msk (0xffffu << MATRIX_WPSR_WPVSRC_Pos) /**< \brief (MATRIX_WPSR) Write Protect Violation Source */

/*@}*/

/* ============================================================================= */
/**  SOFTWARE API DEFINITION FOR Parallel Input/Output Controller */
/* ============================================================================= */
/** \addtogroup SAM9N12_PIO Parallel Input/Output Controller */
/*@{*/

#ifndef __ASSEMBLY__
/** \brief Pio hardware registers */
typedef struct {
  WoReg PIO_PER;       /**< \brief (Pio Offset: 0x0000) PIO Enable Register */
  WoReg PIO_PDR;       /**< \brief (Pio Offset: 0x0004) PIO Disable Register */
  RoReg PIO_PSR;       /**< \brief (Pio Offset: 0x0008) PIO Status Register */
  RoReg Reserved1[1];
  WoReg PIO_OER;       /**< \brief (Pio Offset: 0x0010) Output Enable Register */
  WoReg PIO_ODR;       /**< \brief (Pio Offset: 0x0014) Output Disable Register */
  RoReg PIO_OSR;       /**< \brief (Pio Offset: 0x0018) Output Status Register */
  RoReg Reserved2[1];
  WoReg PIO_IFER;      /**< \brief (Pio Offset: 0x0020) Glitch Input Filter Enable Register */
  WoReg PIO_IFDR;      /**< \brief (Pio Offset: 0x0024) Glitch Input Filter Disable Register */
  RoReg PIO_IFSR;      /**< \brief (Pio Offset: 0x0028) Glitch Input Filter Status Register */
  RoReg Reserved3[1];
  WoReg PIO_SODR;      /**< \brief (Pio Offset: 0x0030) Set Output Data Register */
  WoReg PIO_CODR;      /**< \brief (Pio Offset: 0x0034) Clear Output Data Register */
  RwReg PIO_ODSR;      /**< \brief (Pio Offset: 0x0038) Output Data Status Register */
  RoReg PIO_PDSR;      /**< \brief (Pio Offset: 0x003C) Pin Data Status Register */
  WoReg PIO_IER;       /**< \brief (Pio Offset: 0x0040) Interrupt Enable Register */
  WoReg PIO_IDR;       /**< \brief (Pio Offset: 0x0044) Interrupt Disable Register */
  RoReg PIO_IMR;       /**< \brief (Pio Offset: 0x0048) Interrupt Mask Register */
  RoReg PIO_ISR;       /**< \brief (Pio Offset: 0x004C) Interrupt Status Register */
  WoReg PIO_MDER;      /**< \brief (Pio Offset: 0x0050) Multi-driver Enable Register */
  WoReg PIO_MDDR;      /**< \brief (Pio Offset: 0x0054) Multi-driver Disable Register */
  RoReg PIO_MDSR;      /**< \brief (Pio Offset: 0x0058) Multi-driver Status Register */
  RoReg Reserved4[1];
  WoReg PIO_PUDR;      /**< \brief (Pio Offset: 0x0060) Pull-up Disable Register */
  WoReg PIO_PUER;      /**< \brief (Pio Offset: 0x0064) Pull-up Enable Register */
  RoReg PIO_PUSR;      /**< \brief (Pio Offset: 0x0068) Pad Pull-up Status Register */
  RoReg Reserved5[1];
  RwReg PIO_ABCDSR[2]; /**< \brief (Pio Offset: 0x0070) Peripheral Select Register */
  RoReg Reserved6[2];
  WoReg PIO_IFSCDR;    /**< \brief (Pio Offset: 0x0080) Input Filter Slow Clock Disable Register */
  WoReg PIO_IFSCER;    /**< \brief (Pio Offset: 0x0084) Input Filter Slow Clock Enable Register */
  RoReg PIO_IFSCSR;    /**< \brief (Pio Offset: 0x0088) Input Filter Slow Clock Status Register */
  RwReg PIO_SCDR;      /**< \brief (Pio Offset: 0x008C) Slow Clock Divider Debouncing Register */
  WoReg PIO_PPDDR;     /**< \brief (Pio Offset: 0x0090) Pad Pull-down Disable Register */
  WoReg PIO_PPDER;     /**< \brief (Pio Offset: 0x0094) Pad Pull-down Enable Register */
  RoReg PIO_PPDSR;     /**< \brief (Pio Offset: 0x0098) Pad Pull-down Status Register */
  RoReg Reserved7[1];
  WoReg PIO_OWER;      /**< \brief (Pio Offset: 0x00A0) Output Write Enable */
  WoReg PIO_OWDR;      /**< \brief (Pio Offset: 0x00A4) Output Write Disable */
  RoReg PIO_OWSR;      /**< \brief (Pio Offset: 0x00A8) Output Write Status Register */
  RoReg Reserved8[1];
  WoReg PIO_AIMER;     /**< \brief (Pio Offset: 0x00B0) Additional Interrupt Modes Enable Register */
  WoReg PIO_AIMDR;     /**< \brief (Pio Offset: 0x00B4) Additional Interrupt Modes Disables Register */
  RoReg PIO_AIMMR;     /**< \brief (Pio Offset: 0x00B8) Additional Interrupt Modes Mask Register */
  RoReg Reserved9[1];
  WoReg PIO_ESR;       /**< \brief (Pio Offset: 0x00C0) Edge Select Register */
  WoReg PIO_LSR;       /**< \brief (Pio Offset: 0x00C4) Level Select Register */
  RoReg PIO_ELSR;      /**< \brief (Pio Offset: 0x00C8) Edge/Level Status Register */
  RoReg Reserved10[1];
  WoReg PIO_FELLSR;    /**< \brief (Pio Offset: 0x00D0) Falling Edge/Low Level Select Register */
  WoReg PIO_REHLSR;    /**< \brief (Pio Offset: 0x00D4) Rising Edge/ High Level Select Register */
  RoReg PIO_FRLHSR;    /**< \brief (Pio Offset: 0x00D8) Fall/Rise - Low/High Status Register */
  RoReg Reserved11[1];
  RoReg PIO_LOCKSR;    /**< \brief (Pio Offset: 0x00E0) Lock Status */
  RwReg PIO_WPMR;      /**< \brief (Pio Offset: 0x00E4) Write Protect Mode Register */
  RoReg PIO_WPSR;      /**< \brief (Pio Offset: 0x00E8) Write Protect Status Register */
  RoReg Reserved12[5];
  RwReg PIO_SCHMITT;   /**< \brief (Pio Offset: 0x0100) Schmitt Trigger Register */
  RoReg Reserved13[3];
  RwReg PIO_DELAYR;    /**< \brief (Pio Offset: 0x0110) IO Delay Register */
  RwReg PIO_DRIVER1;   /**< \brief (Pio Offset: 0x0114) I/O Drive Register 1 */
  RwReg PIO_DRIVER2;   /**< \brief (Pio Offset: 0x0118) I/O Drive Register 2 */
} Pio;
#endif /* __ASSEMBLY__ */
/* -------- PIO_PER : (PIO Offset: 0x0000) PIO Enable Register -------- */
#define PIO_PER_P0 (0x1u << 0) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P1 (0x1u << 1) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P2 (0x1u << 2) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P3 (0x1u << 3) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P4 (0x1u << 4) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P5 (0x1u << 5) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P6 (0x1u << 6) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P7 (0x1u << 7) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P8 (0x1u << 8) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P9 (0x1u << 9) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P10 (0x1u << 10) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P11 (0x1u << 11) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P12 (0x1u << 12) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P13 (0x1u << 13) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P14 (0x1u << 14) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P15 (0x1u << 15) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P16 (0x1u << 16) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P17 (0x1u << 17) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P18 (0x1u << 18) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P19 (0x1u << 19) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P20 (0x1u << 20) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P21 (0x1u << 21) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P22 (0x1u << 22) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P23 (0x1u << 23) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P24 (0x1u << 24) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P25 (0x1u << 25) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P26 (0x1u << 26) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P27 (0x1u << 27) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P28 (0x1u << 28) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P29 (0x1u << 29) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P30 (0x1u << 30) /**< \brief (PIO_PER) PIO Enable */
#define PIO_PER_P31 (0x1u << 31) /**< \brief (PIO_PER) PIO Enable */
/* -------- PIO_PDR : (PIO Offset: 0x0004) PIO Disable Register -------- */
#define PIO_PDR_P0 (0x1u << 0) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P1 (0x1u << 1) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P2 (0x1u << 2) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P3 (0x1u << 3) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P4 (0x1u << 4) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P5 (0x1u << 5) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P6 (0x1u << 6) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P7 (0x1u << 7) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P8 (0x1u << 8) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P9 (0x1u << 9) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P10 (0x1u << 10) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P11 (0x1u << 11) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P12 (0x1u << 12) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P13 (0x1u << 13) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P14 (0x1u << 14) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P15 (0x1u << 15) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P16 (0x1u << 16) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P17 (0x1u << 17) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P18 (0x1u << 18) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P19 (0x1u << 19) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P20 (0x1u << 20) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P21 (0x1u << 21) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P22 (0x1u << 22) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P23 (0x1u << 23) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P24 (0x1u << 24) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P25 (0x1u << 25) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P26 (0x1u << 26) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P27 (0x1u << 27) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P28 (0x1u << 28) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P29 (0x1u << 29) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P30 (0x1u << 30) /**< \brief (PIO_PDR) PIO Disable */
#define PIO_PDR_P31 (0x1u << 31) /**< \brief (PIO_PDR) PIO Disable */
/* -------- PIO_PSR : (PIO Offset: 0x0008) PIO Status Register -------- */
#define PIO_PSR_P0 (0x1u << 0) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P1 (0x1u << 1) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P2 (0x1u << 2) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P3 (0x1u << 3) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P4 (0x1u << 4) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P5 (0x1u << 5) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P6 (0x1u << 6) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P7 (0x1u << 7) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P8 (0x1u << 8) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P9 (0x1u << 9) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P10 (0x1u << 10) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P11 (0x1u << 11) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P12 (0x1u << 12) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P13 (0x1u << 13) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P14 (0x1u << 14) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P15 (0x1u << 15) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P16 (0x1u << 16) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P17 (0x1u << 17) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P18 (0x1u << 18) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P19 (0x1u << 19) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P20 (0x1u << 20) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P21 (0x1u << 21) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P22 (0x1u << 22) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P23 (0x1u << 23) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P24 (0x1u << 24) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P25 (0x1u << 25) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P26 (0x1u << 26) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P27 (0x1u << 27) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P28 (0x1u << 28) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P29 (0x1u << 29) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P30 (0x1u << 30) /**< \brief (PIO_PSR) PIO Status */
#define PIO_PSR_P31 (0x1u << 31) /**< \brief (PIO_PSR) PIO Status */
/* -------- PIO_OER : (PIO Offset: 0x0010) Output Enable Register -------- */
#define PIO_OER_P0 (0x1u << 0) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P1 (0x1u << 1) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P2 (0x1u << 2) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P3 (0x1u << 3) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P4 (0x1u << 4) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P5 (0x1u << 5) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P6 (0x1u << 6) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P7 (0x1u << 7) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P8 (0x1u << 8) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P9 (0x1u << 9) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P10 (0x1u << 10) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P11 (0x1u << 11) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P12 (0x1u << 12) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P13 (0x1u << 13) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P14 (0x1u << 14) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P15 (0x1u << 15) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P16 (0x1u << 16) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P17 (0x1u << 17) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P18 (0x1u << 18) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P19 (0x1u << 19) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P20 (0x1u << 20) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P21 (0x1u << 21) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P22 (0x1u << 22) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P23 (0x1u << 23) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P24 (0x1u << 24) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P25 (0x1u << 25) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P26 (0x1u << 26) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P27 (0x1u << 27) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P28 (0x1u << 28) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P29 (0x1u << 29) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P30 (0x1u << 30) /**< \brief (PIO_OER) Output Enable */
#define PIO_OER_P31 (0x1u << 31) /**< \brief (PIO_OER) Output Enable */
/* -------- PIO_ODR : (PIO Offset: 0x0014) Output Disable Register -------- */
#define PIO_ODR_P0 (0x1u << 0) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P1 (0x1u << 1) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P2 (0x1u << 2) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P3 (0x1u << 3) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P4 (0x1u << 4) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P5 (0x1u << 5) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P6 (0x1u << 6) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P7 (0x1u << 7) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P8 (0x1u << 8) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P9 (0x1u << 9) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P10 (0x1u << 10) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P11 (0x1u << 11) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P12 (0x1u << 12) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P13 (0x1u << 13) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P14 (0x1u << 14) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P15 (0x1u << 15) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P16 (0x1u << 16) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P17 (0x1u << 17) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P18 (0x1u << 18) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P19 (0x1u << 19) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P20 (0x1u << 20) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P21 (0x1u << 21) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P22 (0x1u << 22) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P23 (0x1u << 23) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P24 (0x1u << 24) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P25 (0x1u << 25) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P26 (0x1u << 26) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P27 (0x1u << 27) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P28 (0x1u << 28) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P29 (0x1u << 29) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P30 (0x1u << 30) /**< \brief (PIO_ODR) Output Disable */
#define PIO_ODR_P31 (0x1u << 31) /**< \brief (PIO_ODR) Output Disable */
/* -------- PIO_OSR : (PIO Offset: 0x0018) Output Status Register -------- */
#define PIO_OSR_P0 (0x1u << 0) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P1 (0x1u << 1) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P2 (0x1u << 2) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P3 (0x1u << 3) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P4 (0x1u << 4) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P5 (0x1u << 5) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P6 (0x1u << 6) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P7 (0x1u << 7) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P8 (0x1u << 8) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P9 (0x1u << 9) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P10 (0x1u << 10) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P11 (0x1u << 11) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P12 (0x1u << 12) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P13 (0x1u << 13) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P14 (0x1u << 14) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P15 (0x1u << 15) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P16 (0x1u << 16) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P17 (0x1u << 17) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P18 (0x1u << 18) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P19 (0x1u << 19) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P20 (0x1u << 20) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P21 (0x1u << 21) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P22 (0x1u << 22) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P23 (0x1u << 23) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P24 (0x1u << 24) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P25 (0x1u << 25) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P26 (0x1u << 26) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P27 (0x1u << 27) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P28 (0x1u << 28) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P29 (0x1u << 29) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P30 (0x1u << 30) /**< \brief (PIO_OSR) Output Status */
#define PIO_OSR_P31 (0x1u << 31) /**< \brief (PIO_OSR) Output Status */
/* -------- PIO_IFER : (PIO Offset: 0x0020) Glitch Input Filter Enable Register -------- */
#define PIO_IFER_P0 (0x1u << 0) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P1 (0x1u << 1) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P2 (0x1u << 2) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P3 (0x1u << 3) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P4 (0x1u << 4) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P5 (0x1u << 5) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P6 (0x1u << 6) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P7 (0x1u << 7) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P8 (0x1u << 8) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P9 (0x1u << 9) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P10 (0x1u << 10) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P11 (0x1u << 11) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P12 (0x1u << 12) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P13 (0x1u << 13) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P14 (0x1u << 14) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P15 (0x1u << 15) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P16 (0x1u << 16) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P17 (0x1u << 17) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P18 (0x1u << 18) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P19 (0x1u << 19) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P20 (0x1u << 20) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P21 (0x1u << 21) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P22 (0x1u << 22) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P23 (0x1u << 23) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P24 (0x1u << 24) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P25 (0x1u << 25) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P26 (0x1u << 26) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P27 (0x1u << 27) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P28 (0x1u << 28) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P29 (0x1u << 29) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P30 (0x1u << 30) /**< \brief (PIO_IFER) Input Filter Enable */
#define PIO_IFER_P31 (0x1u << 31) /**< \brief (PIO_IFER) Input Filter Enable */
/* -------- PIO_IFDR : (PIO Offset: 0x0024) Glitch Input Filter Disable Register -------- */
#define PIO_IFDR_P0 (0x1u << 0) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P1 (0x1u << 1) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P2 (0x1u << 2) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P3 (0x1u << 3) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P4 (0x1u << 4) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P5 (0x1u << 5) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P6 (0x1u << 6) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P7 (0x1u << 7) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P8 (0x1u << 8) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P9 (0x1u << 9) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P10 (0x1u << 10) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P11 (0x1u << 11) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P12 (0x1u << 12) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P13 (0x1u << 13) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P14 (0x1u << 14) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P15 (0x1u << 15) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P16 (0x1u << 16) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P17 (0x1u << 17) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P18 (0x1u << 18) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P19 (0x1u << 19) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P20 (0x1u << 20) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P21 (0x1u << 21) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P22 (0x1u << 22) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P23 (0x1u << 23) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P24 (0x1u << 24) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P25 (0x1u << 25) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P26 (0x1u << 26) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P27 (0x1u << 27) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P28 (0x1u << 28) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P29 (0x1u << 29) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P30 (0x1u << 30) /**< \brief (PIO_IFDR) Input Filter Disable */
#define PIO_IFDR_P31 (0x1u << 31) /**< \brief (PIO_IFDR) Input Filter Disable */
/* -------- PIO_IFSR : (PIO Offset: 0x0028) Glitch Input Filter Status Register -------- */
#define PIO_IFSR_P0 (0x1u << 0) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P1 (0x1u << 1) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P2 (0x1u << 2) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P3 (0x1u << 3) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P4 (0x1u << 4) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P5 (0x1u << 5) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P6 (0x1u << 6) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P7 (0x1u << 7) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P8 (0x1u << 8) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P9 (0x1u << 9) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P10 (0x1u << 10) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P11 (0x1u << 11) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P12 (0x1u << 12) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P13 (0x1u << 13) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P14 (0x1u << 14) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P15 (0x1u << 15) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P16 (0x1u << 16) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P17 (0x1u << 17) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P18 (0x1u << 18) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P19 (0x1u << 19) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P20 (0x1u << 20) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P21 (0x1u << 21) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P22 (0x1u << 22) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P23 (0x1u << 23) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P24 (0x1u << 24) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P25 (0x1u << 25) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P26 (0x1u << 26) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P27 (0x1u << 27) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P28 (0x1u << 28) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P29 (0x1u << 29) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P30 (0x1u << 30) /**< \brief (PIO_IFSR) Input Filer Status */
#define PIO_IFSR_P31 (0x1u << 31) /**< \brief (PIO_IFSR) Input Filer Status */
/* -------- PIO_SODR : (PIO Offset: 0x0030) Set Output Data Register -------- */
#define PIO_SODR_P0 (0x1u << 0) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P1 (0x1u << 1) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P2 (0x1u << 2) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P3 (0x1u << 3) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P4 (0x1u << 4) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P5 (0x1u << 5) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P6 (0x1u << 6) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P7 (0x1u << 7) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P8 (0x1u << 8) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P9 (0x1u << 9) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P10 (0x1u << 10) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P11 (0x1u << 11) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P12 (0x1u << 12) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P13 (0x1u << 13) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P14 (0x1u << 14) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P15 (0x1u << 15) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P16 (0x1u << 16) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P17 (0x1u << 17) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P18 (0x1u << 18) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P19 (0x1u << 19) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P20 (0x1u << 20) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P21 (0x1u << 21) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P22 (0x1u << 22) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P23 (0x1u << 23) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P24 (0x1u << 24) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P25 (0x1u << 25) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P26 (0x1u << 26) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P27 (0x1u << 27) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P28 (0x1u << 28) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P29 (0x1u << 29) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P30 (0x1u << 30) /**< \brief (PIO_SODR) Set Output Data */
#define PIO_SODR_P31 (0x1u << 31) /**< \brief (PIO_SODR) Set Output Data */
/* -------- PIO_CODR : (PIO Offset: 0x0034) Clear Output Data Register -------- */
#define PIO_CODR_P0 (0x1u << 0) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P1 (0x1u << 1) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P2 (0x1u << 2) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P3 (0x1u << 3) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P4 (0x1u << 4) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P5 (0x1u << 5) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P6 (0x1u << 6) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P7 (0x1u << 7) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P8 (0x1u << 8) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P9 (0x1u << 9) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P10 (0x1u << 10) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P11 (0x1u << 11) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P12 (0x1u << 12) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P13 (0x1u << 13) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P14 (0x1u << 14) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P15 (0x1u << 15) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P16 (0x1u << 16) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P17 (0x1u << 17) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P18 (0x1u << 18) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P19 (0x1u << 19) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P20 (0x1u << 20) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P21 (0x1u << 21) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P22 (0x1u << 22) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P23 (0x1u << 23) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P24 (0x1u << 24) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P25 (0x1u << 25) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P26 (0x1u << 26) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P27 (0x1u << 27) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P28 (0x1u << 28) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P29 (0x1u << 29) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P30 (0x1u << 30) /**< \brief (PIO_CODR) Clear Output Data */
#define PIO_CODR_P31 (0x1u << 31) /**< \brief (PIO_CODR) Clear Output Data */
/* -------- PIO_ODSR : (PIO Offset: 0x0038) Output Data Status Register -------- */
#define PIO_ODSR_P0 (0x1u << 0) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P1 (0x1u << 1) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P2 (0x1u << 2) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P3 (0x1u << 3) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P4 (0x1u << 4) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P5 (0x1u << 5) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P6 (0x1u << 6) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P7 (0x1u << 7) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P8 (0x1u << 8) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P9 (0x1u << 9) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P10 (0x1u << 10) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P11 (0x1u << 11) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P12 (0x1u << 12) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P13 (0x1u << 13) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P14 (0x1u << 14) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P15 (0x1u << 15) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P16 (0x1u << 16) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P17 (0x1u << 17) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P18 (0x1u << 18) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P19 (0x1u << 19) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P20 (0x1u << 20) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P21 (0x1u << 21) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P22 (0x1u << 22) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P23 (0x1u << 23) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P24 (0x1u << 24) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P25 (0x1u << 25) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P26 (0x1u << 26) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P27 (0x1u << 27) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P28 (0x1u << 28) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P29 (0x1u << 29) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P30 (0x1u << 30) /**< \brief (PIO_ODSR) Output Data Status */
#define PIO_ODSR_P31 (0x1u << 31) /**< \brief (PIO_ODSR) Output Data Status */
/* -------- PIO_PDSR : (PIO Offset: 0x003C) Pin Data Status Register -------- */
#define PIO_PDSR_P0 (0x1u << 0) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P1 (0x1u << 1) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P2 (0x1u << 2) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P3 (0x1u << 3) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P4 (0x1u << 4) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P5 (0x1u << 5) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P6 (0x1u << 6) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P7 (0x1u << 7) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P8 (0x1u << 8) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P9 (0x1u << 9) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P10 (0x1u << 10) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P11 (0x1u << 11) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P12 (0x1u << 12) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P13 (0x1u << 13) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P14 (0x1u << 14) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P15 (0x1u << 15) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P16 (0x1u << 16) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P17 (0x1u << 17) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P18 (0x1u << 18) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P19 (0x1u << 19) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P20 (0x1u << 20) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P21 (0x1u << 21) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P22 (0x1u << 22) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P23 (0x1u << 23) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P24 (0x1u << 24) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P25 (0x1u << 25) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P26 (0x1u << 26) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P27 (0x1u << 27) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P28 (0x1u << 28) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P29 (0x1u << 29) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P30 (0x1u << 30) /**< \brief (PIO_PDSR) Output Data Status */
#define PIO_PDSR_P31 (0x1u << 31) /**< \brief (PIO_PDSR) Output Data Status */
/* -------- PIO_IER : (PIO Offset: 0x0040) Interrupt Enable Register -------- */
#define PIO_IER_P0 (0x1u << 0) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P1 (0x1u << 1) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P2 (0x1u << 2) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P3 (0x1u << 3) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P4 (0x1u << 4) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P5 (0x1u << 5) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P6 (0x1u << 6) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P7 (0x1u << 7) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P8 (0x1u << 8) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P9 (0x1u << 9) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P10 (0x1u << 10) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P11 (0x1u << 11) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P12 (0x1u << 12) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P13 (0x1u << 13) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P14 (0x1u << 14) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P15 (0x1u << 15) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P16 (0x1u << 16) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P17 (0x1u << 17) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P18 (0x1u << 18) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P19 (0x1u << 19) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P20 (0x1u << 20) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P21 (0x1u << 21) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P22 (0x1u << 22) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P23 (0x1u << 23) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P24 (0x1u << 24) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P25 (0x1u << 25) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P26 (0x1u << 26) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P27 (0x1u << 27) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P28 (0x1u << 28) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P29 (0x1u << 29) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P30 (0x1u << 30) /**< \brief (PIO_IER) Input Change Interrupt Enable */
#define PIO_IER_P31 (0x1u << 31) /**< \brief (PIO_IER) Input Change Interrupt Enable */
/* -------- PIO_IDR : (PIO Offset: 0x0044) Interrupt Disable Register -------- */
#define PIO_IDR_P0 (0x1u << 0) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P1 (0x1u << 1) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P2 (0x1u << 2) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P3 (0x1u << 3) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P4 (0x1u << 4) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P5 (0x1u << 5) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P6 (0x1u << 6) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P7 (0x1u << 7) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P8 (0x1u << 8) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P9 (0x1u << 9) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P10 (0x1u << 10) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P11 (0x1u << 11) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P12 (0x1u << 12) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P13 (0x1u << 13) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P14 (0x1u << 14) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P15 (0x1u << 15) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P16 (0x1u << 16) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P17 (0x1u << 17) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P18 (0x1u << 18) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P19 (0x1u << 19) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P20 (0x1u << 20) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P21 (0x1u << 21) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P22 (0x1u << 22) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P23 (0x1u << 23) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P24 (0x1u << 24) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P25 (0x1u << 25) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P26 (0x1u << 26) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P27 (0x1u << 27) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P28 (0x1u << 28) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P29 (0x1u << 29) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P30 (0x1u << 30) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
#define PIO_IDR_P31 (0x1u << 31) /**< \brief (PIO_IDR) Input Change Interrupt Disable */
/* -------- PIO_IMR : (PIO Offset: 0x0048) Interrupt Mask Register -------- */
#define PIO_IMR_P0 (0x1u << 0) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P1 (0x1u << 1) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P2 (0x1u << 2) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P3 (0x1u << 3) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P4 (0x1u << 4) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P5 (0x1u << 5) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P6 (0x1u << 6) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P7 (0x1u << 7) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P8 (0x1u << 8) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P9 (0x1u << 9) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P10 (0x1u << 10) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P11 (0x1u << 11) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P12 (0x1u << 12) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P13 (0x1u << 13) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P14 (0x1u << 14) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P15 (0x1u << 15) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P16 (0x1u << 16) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P17 (0x1u << 17) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P18 (0x1u << 18) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P19 (0x1u << 19) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P20 (0x1u << 20) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P21 (0x1u << 21) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P22 (0x1u << 22) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P23 (0x1u << 23) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P24 (0x1u << 24) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P25 (0x1u << 25) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P26 (0x1u << 26) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P27 (0x1u << 27) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P28 (0x1u << 28) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P29 (0x1u << 29) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P30 (0x1u << 30) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
#define PIO_IMR_P31 (0x1u << 31) /**< \brief (PIO_IMR) Input Change Interrupt Mask */
/* -------- PIO_ISR : (PIO Offset: 0x004C) Interrupt Status Register -------- */
#define PIO_ISR_P0 (0x1u << 0) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P1 (0x1u << 1) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P2 (0x1u << 2) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P3 (0x1u << 3) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P4 (0x1u << 4) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P5 (0x1u << 5) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P6 (0x1u << 6) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P7 (0x1u << 7) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P8 (0x1u << 8) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P9 (0x1u << 9) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P10 (0x1u << 10) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P11 (0x1u << 11) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P12 (0x1u << 12) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P13 (0x1u << 13) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P14 (0x1u << 14) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P15 (0x1u << 15) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P16 (0x1u << 16) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P17 (0x1u << 17) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P18 (0x1u << 18) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P19 (0x1u << 19) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P20 (0x1u << 20) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P21 (0x1u << 21) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P22 (0x1u << 22) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P23 (0x1u << 23) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P24 (0x1u << 24) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P25 (0x1u << 25) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P26 (0x1u << 26) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P27 (0x1u << 27) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P28 (0x1u << 28) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P29 (0x1u << 29) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P30 (0x1u << 30) /**< \brief (PIO_ISR) Input Change Interrupt Status */
#define PIO_ISR_P31 (0x1u << 31) /**< \brief (PIO_ISR) Input Change Interrupt Status */
/* -------- PIO_MDER : (PIO Offset: 0x0050) Multi-driver Enable Register -------- */
#define PIO_MDER_P0 (0x1u << 0) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P1 (0x1u << 1) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P2 (0x1u << 2) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P3 (0x1u << 3) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P4 (0x1u << 4) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P5 (0x1u << 5) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P6 (0x1u << 6) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P7 (0x1u << 7) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P8 (0x1u << 8) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P9 (0x1u << 9) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P10 (0x1u << 10) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P11 (0x1u << 11) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P12 (0x1u << 12) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P13 (0x1u << 13) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P14 (0x1u << 14) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P15 (0x1u << 15) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P16 (0x1u << 16) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P17 (0x1u << 17) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P18 (0x1u << 18) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P19 (0x1u << 19) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P20 (0x1u << 20) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P21 (0x1u << 21) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P22 (0x1u << 22) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P23 (0x1u << 23) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P24 (0x1u << 24) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P25 (0x1u << 25) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P26 (0x1u << 26) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P27 (0x1u << 27) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P28 (0x1u << 28) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P29 (0x1u << 29) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P30 (0x1u << 30) /**< \brief (PIO_MDER) Multi Drive Enable. */
#define PIO_MDER_P31 (0x1u << 31) /**< \brief (PIO_MDER) Multi Drive Enable. */
/* -------- PIO_MDDR : (PIO Offset: 0x0054) Multi-driver Disable Register -------- */
#define PIO_MDDR_P0 (0x1u << 0) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P1 (0x1u << 1) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P2 (0x1u << 2) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P3 (0x1u << 3) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P4 (0x1u << 4) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P5 (0x1u << 5) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P6 (0x1u << 6) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P7 (0x1u << 7) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P8 (0x1u << 8) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P9 (0x1u << 9) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P10 (0x1u << 10) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P11 (0x1u << 11) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P12 (0x1u << 12) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P13 (0x1u << 13) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P14 (0x1u << 14) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P15 (0x1u << 15) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P16 (0x1u << 16) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P17 (0x1u << 17) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P18 (0x1u << 18) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P19 (0x1u << 19) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P20 (0x1u << 20) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P21 (0x1u << 21) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P22 (0x1u << 22) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P23 (0x1u << 23) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P24 (0x1u << 24) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P25 (0x1u << 25) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P26 (0x1u << 26) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P27 (0x1u << 27) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P28 (0x1u << 28) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P29 (0x1u << 29) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P30 (0x1u << 30) /**< \brief (PIO_MDDR) Multi Drive Disable. */
#define PIO_MDDR_P31 (0x1u << 31) /**< \brief (PIO_MDDR) Multi Drive Disable. */
/* -------- PIO_MDSR : (PIO Offset: 0x0058) Multi-driver Status Register -------- */
#define PIO_MDSR_P0 (0x1u << 0) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P1 (0x1u << 1) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P2 (0x1u << 2) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P3 (0x1u << 3) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P4 (0x1u << 4) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P5 (0x1u << 5) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P6 (0x1u << 6) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P7 (0x1u << 7) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P8 (0x1u << 8) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P9 (0x1u << 9) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P10 (0x1u << 10) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P11 (0x1u << 11) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P12 (0x1u << 12) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P13 (0x1u << 13) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P14 (0x1u << 14) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P15 (0x1u << 15) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P16 (0x1u << 16) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P17 (0x1u << 17) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P18 (0x1u << 18) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P19 (0x1u << 19) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P20 (0x1u << 20) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P21 (0x1u << 21) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P22 (0x1u << 22) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P23 (0x1u << 23) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P24 (0x1u << 24) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P25 (0x1u << 25) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P26 (0x1u << 26) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P27 (0x1u << 27) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P28 (0x1u << 28) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P29 (0x1u << 29) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P30 (0x1u << 30) /**< \brief (PIO_MDSR) Multi Drive Status. */
#define PIO_MDSR_P31 (0x1u << 31) /**< \brief (PIO_MDSR) Multi Drive Status. */
/* -------- PIO_PUDR : (PIO Offset: 0x0060) Pull-up Disable Register -------- */
#define PIO_PUDR_P0 (0x1u << 0) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P1 (0x1u << 1) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P2 (0x1u << 2) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P3 (0x1u << 3) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P4 (0x1u << 4) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P5 (0x1u << 5) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P6 (0x1u << 6) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P7 (0x1u << 7) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P8 (0x1u << 8) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P9 (0x1u << 9) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P10 (0x1u << 10) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P11 (0x1u << 11) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P12 (0x1u << 12) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P13 (0x1u << 13) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P14 (0x1u << 14) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P15 (0x1u << 15) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P16 (0x1u << 16) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P17 (0x1u << 17) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P18 (0x1u << 18) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P19 (0x1u << 19) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P20 (0x1u << 20) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P21 (0x1u << 21) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P22 (0x1u << 22) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P23 (0x1u << 23) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P24 (0x1u << 24) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P25 (0x1u << 25) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P26 (0x1u << 26) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P27 (0x1u << 27) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P28 (0x1u << 28) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P29 (0x1u << 29) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P30 (0x1u << 30) /**< \brief (PIO_PUDR) Pull Up Disable. */
#define PIO_PUDR_P31 (0x1u << 31) /**< \brief (PIO_PUDR) Pull Up Disable. */
/* -------- PIO_PUER : (PIO Offset: 0x0064) Pull-up Enable Register -------- */
#define PIO_PUER_P0 (0x1u << 0) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P1 (0x1u << 1) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P2 (0x1u << 2) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P3 (0x1u << 3) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P4 (0x1u << 4) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P5 (0x1u << 5) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P6 (0x1u << 6) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P7 (0x1u << 7) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P8 (0x1u << 8) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P9 (0x1u << 9) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P10 (0x1u << 10) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P11 (0x1u << 11) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P12 (0x1u << 12) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P13 (0x1u << 13) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P14 (0x1u << 14) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P15 (0x1u << 15) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P16 (0x1u << 16) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P17 (0x1u << 17) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P18 (0x1u << 18) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P19 (0x1u << 19) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P20 (0x1u << 20) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P21 (0x1u << 21) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P22 (0x1u << 22) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P23 (0x1u << 23) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P24 (0x1u << 24) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P25 (0x1u << 25) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P26 (0x1u << 26) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P27 (0x1u << 27) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P28 (0x1u << 28) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P29 (0x1u << 29) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P30 (0x1u << 30) /**< \brief (PIO_PUER) Pull Up Enable. */
#define PIO_PUER_P31 (0x1u << 31) /**< \brief (PIO_PUER) Pull Up Enable. */
/* -------- PIO_PUSR : (PIO Offset: 0x0068) Pad Pull-up Status Register -------- */
#define PIO_PUSR_P0 (0x1u << 0) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P1 (0x1u << 1) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P2 (0x1u << 2) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P3 (0x1u << 3) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P4 (0x1u << 4) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P5 (0x1u << 5) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P6 (0x1u << 6) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P7 (0x1u << 7) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P8 (0x1u << 8) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P9 (0x1u << 9) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P10 (0x1u << 10) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P11 (0x1u << 11) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P12 (0x1u << 12) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P13 (0x1u << 13) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P14 (0x1u << 14) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P15 (0x1u << 15) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P16 (0x1u << 16) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P17 (0x1u << 17) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P18 (0x1u << 18) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P19 (0x1u << 19) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P20 (0x1u << 20) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P21 (0x1u << 21) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P22 (0x1u << 22) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P23 (0x1u << 23) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P24 (0x1u << 24) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P25 (0x1u << 25) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P26 (0x1u << 26) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P27 (0x1u << 27) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P28 (0x1u << 28) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P29 (0x1u << 29) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P30 (0x1u << 30) /**< \brief (PIO_PUSR) Pull Up Status. */
#define PIO_PUSR_P31 (0x1u << 31) /**< \brief (PIO_PUSR) Pull Up Status. */
/* -------- PIO_ABCDSR[2] : (PIO Offset: 0x0070) Peripheral Select Register -------- */
#define PIO_ABCDSR_P0 (0x1u << 0) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P1 (0x1u << 1) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P2 (0x1u << 2) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P3 (0x1u << 3) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P4 (0x1u << 4) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P5 (0x1u << 5) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P6 (0x1u << 6) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P7 (0x1u << 7) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P8 (0x1u << 8) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P9 (0x1u << 9) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P10 (0x1u << 10) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P11 (0x1u << 11) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P12 (0x1u << 12) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P13 (0x1u << 13) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P14 (0x1u << 14) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P15 (0x1u << 15) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P16 (0x1u << 16) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P17 (0x1u << 17) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P18 (0x1u << 18) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P19 (0x1u << 19) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P20 (0x1u << 20) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P21 (0x1u << 21) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P22 (0x1u << 22) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P23 (0x1u << 23) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P24 (0x1u << 24) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P25 (0x1u << 25) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P26 (0x1u << 26) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P27 (0x1u << 27) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P28 (0x1u << 28) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P29 (0x1u << 29) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P30 (0x1u << 30) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
#define PIO_ABCDSR_P31 (0x1u << 31) /**< \brief (PIO_ABCDSR[2]) Peripheral Select. */
/* -------- PIO_IFSCDR : (PIO Offset: 0x0080) Input Filter Slow Clock Disable Register -------- */
#define PIO_IFSCDR_P0 (0x1u << 0) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P1 (0x1u << 1) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P2 (0x1u << 2) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P3 (0x1u << 3) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P4 (0x1u << 4) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P5 (0x1u << 5) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P6 (0x1u << 6) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P7 (0x1u << 7) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P8 (0x1u << 8) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P9 (0x1u << 9) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P10 (0x1u << 10) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P11 (0x1u << 11) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P12 (0x1u << 12) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P13 (0x1u << 13) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P14 (0x1u << 14) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P15 (0x1u << 15) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P16 (0x1u << 16) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P17 (0x1u << 17) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P18 (0x1u << 18) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P19 (0x1u << 19) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P20 (0x1u << 20) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P21 (0x1u << 21) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P22 (0x1u << 22) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P23 (0x1u << 23) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P24 (0x1u << 24) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P25 (0x1u << 25) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P26 (0x1u << 26) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P27 (0x1u << 27) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P28 (0x1u << 28) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P29 (0x1u << 29) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P30 (0x1u << 30) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
#define PIO_IFSCDR_P31 (0x1u << 31) /**< \brief (PIO_IFSCDR) PIO Clock Glitch Filtering Select. */
/* -------- PIO_IFSCER : (PIO Offset: 0x0084) Input Filter Slow Clock Enable Register -------- */
#define PIO_IFSCER_P0 (0x1u << 0) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P1 (0x1u << 1) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P2 (0x1u << 2) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P3 (0x1u << 3) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P4 (0x1u << 4) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P5 (0x1u << 5) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P6 (0x1u << 6) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P7 (0x1u << 7) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P8 (0x1u << 8) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P9 (0x1u << 9) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P10 (0x1u << 10) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P11 (0x1u << 11) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P12 (0x1u << 12) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P13 (0x1u << 13) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P14 (0x1u << 14) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P15 (0x1u << 15) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P16 (0x1u << 16) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P17 (0x1u << 17) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P18 (0x1u << 18) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P19 (0x1u << 19) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P20 (0x1u << 20) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P21 (0x1u << 21) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P22 (0x1u << 22) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P23 (0x1u << 23) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P24 (0x1u << 24) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P25 (0x1u << 25) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P26 (0x1u << 26) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P27 (0x1u << 27) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P28 (0x1u << 28) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P29 (0x1u << 29) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P30 (0x1u << 30) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
#define PIO_IFSCER_P31 (0x1u << 31) /**< \brief (PIO_IFSCER) Debouncing Filtering Select. */
/* -------- PIO_IFSCSR : (PIO Offset: 0x0088) Input Filter Slow Clock Status Register -------- */
#define PIO_IFSCSR_P0 (0x1u << 0) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P1 (0x1u << 1) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P2 (0x1u << 2) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P3 (0x1u << 3) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P4 (0x1u << 4) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P5 (0x1u << 5) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P6 (0x1u << 6) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P7 (0x1u << 7) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P8 (0x1u << 8) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P9 (0x1u << 9) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P10 (0x1u << 10) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P11 (0x1u << 11) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P12 (0x1u << 12) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P13 (0x1u << 13) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P14 (0x1u << 14) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P15 (0x1u << 15) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P16 (0x1u << 16) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P17 (0x1u << 17) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P18 (0x1u << 18) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P19 (0x1u << 19) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P20 (0x1u << 20) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P21 (0x1u << 21) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P22 (0x1u << 22) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P23 (0x1u << 23) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P24 (0x1u << 24) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P25 (0x1u << 25) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P26 (0x1u << 26) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P27 (0x1u << 27) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P28 (0x1u << 28) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P29 (0x1u << 29) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P30 (0x1u << 30) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
#define PIO_IFSCSR_P31 (0x1u << 31) /**< \brief (PIO_IFSCSR) Glitch or Debouncing Filter Selection Status */
/* -------- PIO_SCDR : (PIO Offset: 0x008C) Slow Clock Divider Debouncing Register -------- */
#define PIO_SCDR_DIV_Pos 0
#define PIO_SCDR_DIV_Msk (0x3fffu << PIO_SCDR_DIV_Pos) /**< \brief (PIO_SCDR)  */
#define PIO_SCDR_DIV(value) ((PIO_SCDR_DIV_Msk & ((value) << PIO_SCDR_DIV_Pos)))
/* -------- PIO_PPDDR : (PIO Offset: 0x0090) Pad Pull-down Disable Register -------- */
#define PIO_PPDDR_P0 (0x1u << 0) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P1 (0x1u << 1) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P2 (0x1u << 2) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P3 (0x1u << 3) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P4 (0x1u << 4) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P5 (0x1u << 5) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P6 (0x1u << 6) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P7 (0x1u << 7) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P8 (0x1u << 8) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P9 (0x1u << 9) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P10 (0x1u << 10) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P11 (0x1u << 11) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P12 (0x1u << 12) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P13 (0x1u << 13) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P14 (0x1u << 14) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P15 (0x1u << 15) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P16 (0x1u << 16) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P17 (0x1u << 17) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P18 (0x1u << 18) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P19 (0x1u << 19) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P20 (0x1u << 20) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P21 (0x1u << 21) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P22 (0x1u << 22) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P23 (0x1u << 23) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P24 (0x1u << 24) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P25 (0x1u << 25) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P26 (0x1u << 26) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P27 (0x1u << 27) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P28 (0x1u << 28) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P29 (0x1u << 29) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P30 (0x1u << 30) /**< \brief (PIO_PPDDR) Pull Down Disable. */
#define PIO_PPDDR_P31 (0x1u << 31) /**< \brief (PIO_PPDDR) Pull Down Disable. */
/* -------- PIO_PPDER : (PIO Offset: 0x0094) Pad Pull-down Enable Register -------- */
#define PIO_PPDER_P0 (0x1u << 0) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P1 (0x1u << 1) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P2 (0x1u << 2) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P3 (0x1u << 3) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P4 (0x1u << 4) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P5 (0x1u << 5) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P6 (0x1u << 6) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P7 (0x1u << 7) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P8 (0x1u << 8) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P9 (0x1u << 9) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P10 (0x1u << 10) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P11 (0x1u << 11) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P12 (0x1u << 12) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P13 (0x1u << 13) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P14 (0x1u << 14) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P15 (0x1u << 15) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P16 (0x1u << 16) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P17 (0x1u << 17) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P18 (0x1u << 18) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P19 (0x1u << 19) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P20 (0x1u << 20) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P21 (0x1u << 21) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P22 (0x1u << 22) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P23 (0x1u << 23) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P24 (0x1u << 24) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P25 (0x1u << 25) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P26 (0x1u << 26) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P27 (0x1u << 27) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P28 (0x1u << 28) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P29 (0x1u << 29) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P30 (0x1u << 30) /**< \brief (PIO_PPDER) Pull Down Enable. */
#define PIO_PPDER_P31 (0x1u << 31) /**< \brief (PIO_PPDER) Pull Down Enable. */
/* -------- PIO_PPDSR : (PIO Offset: 0x0098) Pad Pull-down Status Register -------- */
#define PIO_PPDSR_P0 (0x1u << 0) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P1 (0x1u << 1) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P2 (0x1u << 2) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P3 (0x1u << 3) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P4 (0x1u << 4) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P5 (0x1u << 5) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P6 (0x1u << 6) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P7 (0x1u << 7) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P8 (0x1u << 8) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P9 (0x1u << 9) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P10 (0x1u << 10) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P11 (0x1u << 11) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P12 (0x1u << 12) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P13 (0x1u << 13) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P14 (0x1u << 14) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P15 (0x1u << 15) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P16 (0x1u << 16) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P17 (0x1u << 17) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P18 (0x1u << 18) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P19 (0x1u << 19) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P20 (0x1u << 20) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P21 (0x1u << 21) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P22 (0x1u << 22) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P23 (0x1u << 23) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P24 (0x1u << 24) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P25 (0x1u << 25) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P26 (0x1u << 26) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P27 (0x1u << 27) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P28 (0x1u << 28) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P29 (0x1u << 29) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P30 (0x1u << 30) /**< \brief (PIO_PPDSR) Pull Down Status. */
#define PIO_PPDSR_P31 (0x1u << 31) /**< \brief (PIO_PPDSR) Pull Down Status. */
/* -------- PIO_OWER : (PIO Offset: 0x00A0) Output Write Enable -------- */
#define PIO_OWER_P0 (0x1u << 0) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P1 (0x1u << 1) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P2 (0x1u << 2) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P3 (0x1u << 3) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P4 (0x1u << 4) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P5 (0x1u << 5) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P6 (0x1u << 6) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P7 (0x1u << 7) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P8 (0x1u << 8) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P9 (0x1u << 9) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P10 (0x1u << 10) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P11 (0x1u << 11) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P12 (0x1u << 12) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P13 (0x1u << 13) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P14 (0x1u << 14) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P15 (0x1u << 15) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P16 (0x1u << 16) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P17 (0x1u << 17) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P18 (0x1u << 18) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P19 (0x1u << 19) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P20 (0x1u << 20) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P21 (0x1u << 21) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P22 (0x1u << 22) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P23 (0x1u << 23) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P24 (0x1u << 24) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P25 (0x1u << 25) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P26 (0x1u << 26) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P27 (0x1u << 27) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P28 (0x1u << 28) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P29 (0x1u << 29) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P30 (0x1u << 30) /**< \brief (PIO_OWER) Output Write Enable. */
#define PIO_OWER_P31 (0x1u << 31) /**< \brief (PIO_OWER) Output Write Enable. */
/* -------- PIO_OWDR : (PIO Offset: 0x00A4) Output Write Disable -------- */
#define PIO_OWDR_P0 (0x1u << 0) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P1 (0x1u << 1) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P2 (0x1u << 2) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P3 (0x1u << 3) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P4 (0x1u << 4) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P5 (0x1u << 5) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P6 (0x1u << 6) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P7 (0x1u << 7) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P8 (0x1u << 8) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P9 (0x1u << 9) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P10 (0x1u << 10) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P11 (0x1u << 11) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P12 (0x1u << 12) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P13 (0x1u << 13) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P14 (0x1u << 14) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P15 (0x1u << 15) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P16 (0x1u << 16) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P17 (0x1u << 17) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P18 (0x1u << 18) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P19 (0x1u << 19) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P20 (0x1u << 20) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P21 (0x1u << 21) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P22 (0x1u << 22) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P23 (0x1u << 23) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P24 (0x1u << 24) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P25 (0x1u << 25) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P26 (0x1u << 26) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P27 (0x1u << 27) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P28 (0x1u << 28) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P29 (0x1u << 29) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P30 (0x1u << 30) /**< \brief (PIO_OWDR) Output Write Disable. */
#define PIO_OWDR_P31 (0x1u << 31) /**< \brief (PIO_OWDR) Output Write Disable. */
/* -------- PIO_OWSR : (PIO Offset: 0x00A8) Output Write Status Register -------- */
#define PIO_OWSR_P0 (0x1u << 0) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P1 (0x1u << 1) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P2 (0x1u << 2) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P3 (0x1u << 3) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P4 (0x1u << 4) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P5 (0x1u << 5) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P6 (0x1u << 6) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P7 (0x1u << 7) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P8 (0x1u << 8) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P9 (0x1u << 9) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P10 (0x1u << 10) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P11 (0x1u << 11) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P12 (0x1u << 12) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P13 (0x1u << 13) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P14 (0x1u << 14) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P15 (0x1u << 15) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P16 (0x1u << 16) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P17 (0x1u << 17) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P18 (0x1u << 18) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P19 (0x1u << 19) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P20 (0x1u << 20) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P21 (0x1u << 21) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P22 (0x1u << 22) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P23 (0x1u << 23) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P24 (0x1u << 24) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P25 (0x1u << 25) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P26 (0x1u << 26) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P27 (0x1u << 27) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P28 (0x1u << 28) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P29 (0x1u << 29) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P30 (0x1u << 30) /**< \brief (PIO_OWSR) Output Write Status. */
#define PIO_OWSR_P31 (0x1u << 31) /**< \brief (PIO_OWSR) Output Write Status. */
/* -------- PIO_AIMER : (PIO Offset: 0x00B0) Additional Interrupt Modes Enable Register -------- */
#define PIO_AIMER_P0 (0x1u << 0) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P1 (0x1u << 1) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P2 (0x1u << 2) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P3 (0x1u << 3) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P4 (0x1u << 4) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P5 (0x1u << 5) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P6 (0x1u << 6) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P7 (0x1u << 7) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P8 (0x1u << 8) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P9 (0x1u << 9) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P10 (0x1u << 10) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P11 (0x1u << 11) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P12 (0x1u << 12) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P13 (0x1u << 13) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P14 (0x1u << 14) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P15 (0x1u << 15) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P16 (0x1u << 16) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P17 (0x1u << 17) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P18 (0x1u << 18) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P19 (0x1u << 19) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P20 (0x1u << 20) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P21 (0x1u << 21) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P22 (0x1u << 22) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P23 (0x1u << 23) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P24 (0x1u << 24) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P25 (0x1u << 25) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P26 (0x1u << 26) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P27 (0x1u << 27) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P28 (0x1u << 28) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P29 (0x1u << 29) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P30 (0x1u << 30) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
#define PIO_AIMER_P31 (0x1u << 31) /**< \brief (PIO_AIMER) Additional Interrupt Modes Enable. */
/* -------- PIO_AIMDR : (PIO Offset: 0x00B4) Additional Interrupt Modes Disables Register -------- */
#define PIO_AIMDR_P0 (0x1u << 0) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P1 (0x1u << 1) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P2 (0x1u << 2) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P3 (0x1u << 3) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P4 (0x1u << 4) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P5 (0x1u << 5) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P6 (0x1u << 6) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P7 (0x1u << 7) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P8 (0x1u << 8) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P9 (0x1u << 9) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P10 (0x1u << 10) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P11 (0x1u << 11) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P12 (0x1u << 12) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P13 (0x1u << 13) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P14 (0x1u << 14) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P15 (0x1u << 15) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P16 (0x1u << 16) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P17 (0x1u << 17) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P18 (0x1u << 18) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P19 (0x1u << 19) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P20 (0x1u << 20) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P21 (0x1u << 21) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P22 (0x1u << 22) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P23 (0x1u << 23) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P24 (0x1u << 24) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P25 (0x1u << 25) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P26 (0x1u << 26) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P27 (0x1u << 27) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P28 (0x1u << 28) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P29 (0x1u << 29) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P30 (0x1u << 30) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
#define PIO_AIMDR_P31 (0x1u << 31) /**< \brief (PIO_AIMDR) Additional Interrupt Modes Disable. */
/* -------- PIO_AIMMR : (PIO Offset: 0x00B8) Additional Interrupt Modes Mask Register -------- */
#define PIO_AIMMR_P0 (0x1u << 0) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P1 (0x1u << 1) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P2 (0x1u << 2) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P3 (0x1u << 3) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P4 (0x1u << 4) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P5 (0x1u << 5) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P6 (0x1u << 6) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P7 (0x1u << 7) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P8 (0x1u << 8) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P9 (0x1u << 9) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P10 (0x1u << 10) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P11 (0x1u << 11) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P12 (0x1u << 12) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P13 (0x1u << 13) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P14 (0x1u << 14) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P15 (0x1u << 15) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P16 (0x1u << 16) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P17 (0x1u << 17) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P18 (0x1u << 18) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P19 (0x1u << 19) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P20 (0x1u << 20) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P21 (0x1u << 21) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P22 (0x1u << 22) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P23 (0x1u << 23) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P24 (0x1u << 24) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P25 (0x1u << 25) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P26 (0x1u << 26) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P27 (0x1u << 27) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P28 (0x1u << 28) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P29 (0x1u << 29) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P30 (0x1u << 30) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
#define PIO_AIMMR_P31 (0x1u << 31) /**< \brief (PIO_AIMMR) Peripheral CD Status. */
/* -------- PIO_ESR : (PIO Offset: 0x00C0) Edge Select Register -------- */
#define PIO_ESR_P0 (0x1u << 0) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P1 (0x1u << 1) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P2 (0x1u << 2) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P3 (0x1u << 3) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P4 (0x1u << 4) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P5 (0x1u << 5) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P6 (0x1u << 6) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P7 (0x1u << 7) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P8 (0x1u << 8) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P9 (0x1u << 9) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P10 (0x1u << 10) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P11 (0x1u << 11) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P12 (0x1u << 12) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P13 (0x1u << 13) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P14 (0x1u << 14) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P15 (0x1u << 15) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P16 (0x1u << 16) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P17 (0x1u << 17) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P18 (0x1u << 18) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P19 (0x1u << 19) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P20 (0x1u << 20) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P21 (0x1u << 21) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P22 (0x1u << 22) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P23 (0x1u << 23) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P24 (0x1u << 24) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P25 (0x1u << 25) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P26 (0x1u << 26) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P27 (0x1u << 27) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P28 (0x1u << 28) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P29 (0x1u << 29) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P30 (0x1u << 30) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
#define PIO_ESR_P31 (0x1u << 31) /**< \brief (PIO_ESR) Edge Interrupt Selection. */
/* -------- PIO_LSR : (PIO Offset: 0x00C4) Level Select Register -------- */
#define PIO_LSR_P0 (0x1u << 0) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P1 (0x1u << 1) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P2 (0x1u << 2) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P3 (0x1u << 3) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P4 (0x1u << 4) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P5 (0x1u << 5) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P6 (0x1u << 6) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P7 (0x1u << 7) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P8 (0x1u << 8) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P9 (0x1u << 9) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P10 (0x1u << 10) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P11 (0x1u << 11) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P12 (0x1u << 12) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P13 (0x1u << 13) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P14 (0x1u << 14) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P15 (0x1u << 15) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P16 (0x1u << 16) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P17 (0x1u << 17) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P18 (0x1u << 18) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P19 (0x1u << 19) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P20 (0x1u << 20) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P21 (0x1u << 21) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P22 (0x1u << 22) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P23 (0x1u << 23) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P24 (0x1u << 24) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P25 (0x1u << 25) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P26 (0x1u << 26) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P27 (0x1u << 27) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P28 (0x1u << 28) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P29 (0x1u << 29) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P30 (0x1u << 30) /**< \brief (PIO_LSR) Level Interrupt Selection. */
#define PIO_LSR_P31 (0x1u << 31) /**< \brief (PIO_LSR) Level Interrupt Selection. */
/* -------- PIO_ELSR : (PIO Offset: 0x00C8) Edge/Level Status Register -------- */
#define PIO_ELSR_P0 (0x1u << 0) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P1 (0x1u << 1) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P2 (0x1u << 2) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P3 (0x1u << 3) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P4 (0x1u << 4) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P5 (0x1u << 5) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P6 (0x1u << 6) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P7 (0x1u << 7) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P8 (0x1u << 8) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P9 (0x1u << 9) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P10 (0x1u << 10) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P11 (0x1u << 11) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P12 (0x1u << 12) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P13 (0x1u << 13) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P14 (0x1u << 14) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P15 (0x1u << 15) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P16 (0x1u << 16) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P17 (0x1u << 17) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P18 (0x1u << 18) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P19 (0x1u << 19) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P20 (0x1u << 20) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P21 (0x1u << 21) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P22 (0x1u << 22) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P23 (0x1u << 23) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P24 (0x1u << 24) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P25 (0x1u << 25) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P26 (0x1u << 26) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P27 (0x1u << 27) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P28 (0x1u << 28) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P29 (0x1u << 29) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P30 (0x1u << 30) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
#define PIO_ELSR_P31 (0x1u << 31) /**< \brief (PIO_ELSR) Edge/Level Interrupt source selection. */
/* -------- PIO_FELLSR : (PIO Offset: 0x00D0) Falling Edge/Low Level Select Register -------- */
#define PIO_FELLSR_P0 (0x1u << 0) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P1 (0x1u << 1) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P2 (0x1u << 2) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P3 (0x1u << 3) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P4 (0x1u << 4) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P5 (0x1u << 5) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P6 (0x1u << 6) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P7 (0x1u << 7) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P8 (0x1u << 8) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P9 (0x1u << 9) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P10 (0x1u << 10) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P11 (0x1u << 11) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P12 (0x1u << 12) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P13 (0x1u << 13) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P14 (0x1u << 14) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P15 (0x1u << 15) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P16 (0x1u << 16) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P17 (0x1u << 17) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P18 (0x1u << 18) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P19 (0x1u << 19) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P20 (0x1u << 20) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P21 (0x1u << 21) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P22 (0x1u << 22) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P23 (0x1u << 23) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P24 (0x1u << 24) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P25 (0x1u << 25) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P26 (0x1u << 26) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P27 (0x1u << 27) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P28 (0x1u << 28) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P29 (0x1u << 29) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P30 (0x1u << 30) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
#define PIO_FELLSR_P31 (0x1u << 31) /**< \brief (PIO_FELLSR) Falling Edge/Low Level Interrupt Selection. */
/* -------- PIO_REHLSR : (PIO Offset: 0x00D4) Rising Edge/ High Level Select Register -------- */
#define PIO_REHLSR_P0 (0x1u << 0) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P1 (0x1u << 1) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P2 (0x1u << 2) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P3 (0x1u << 3) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P4 (0x1u << 4) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P5 (0x1u << 5) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P6 (0x1u << 6) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P7 (0x1u << 7) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P8 (0x1u << 8) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P9 (0x1u << 9) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P10 (0x1u << 10) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P11 (0x1u << 11) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P12 (0x1u << 12) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P13 (0x1u << 13) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P14 (0x1u << 14) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P15 (0x1u << 15) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P16 (0x1u << 16) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P17 (0x1u << 17) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P18 (0x1u << 18) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P19 (0x1u << 19) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P20 (0x1u << 20) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P21 (0x1u << 21) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P22 (0x1u << 22) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P23 (0x1u << 23) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P24 (0x1u << 24) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P25 (0x1u << 25) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P26 (0x1u << 26) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P27 (0x1u << 27) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P28 (0x1u << 28) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P29 (0x1u << 29) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P30 (0x1u << 30) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
#define PIO_REHLSR_P31 (0x1u << 31) /**< \brief (PIO_REHLSR) Rising Edge /High Level Interrupt Selection. */
/* -------- PIO_FRLHSR : (PIO Offset: 0x00D8) Fall/Rise - Low/High Status Register -------- */
#define PIO_FRLHSR_P0 (0x1u << 0) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P1 (0x1u << 1) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P2 (0x1u << 2) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P3 (0x1u << 3) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P4 (0x1u << 4) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P5 (0x1u << 5) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P6 (0x1u << 6) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P7 (0x1u << 7) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P8 (0x1u << 8) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P9 (0x1u << 9) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P10 (0x1u << 10) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P11 (0x1u << 11) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P12 (0x1u << 12) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P13 (0x1u << 13) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P14 (0x1u << 14) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P15 (0x1u << 15) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P16 (0x1u << 16) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P17 (0x1u << 17) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P18 (0x1u << 18) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P19 (0x1u << 19) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P20 (0x1u << 20) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P21 (0x1u << 21) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P22 (0x1u << 22) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P23 (0x1u << 23) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P24 (0x1u << 24) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P25 (0x1u << 25) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P26 (0x1u << 26) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P27 (0x1u << 27) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P28 (0x1u << 28) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P29 (0x1u << 29) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P30 (0x1u << 30) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
#define PIO_FRLHSR_P31 (0x1u << 31) /**< \brief (PIO_FRLHSR) Edge /Level Interrupt Source Selection. */
/* -------- PIO_LOCKSR : (PIO Offset: 0x00E0) Lock Status -------- */
#define PIO_LOCKSR_P0 (0x1u << 0) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P1 (0x1u << 1) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P2 (0x1u << 2) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P3 (0x1u << 3) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P4 (0x1u << 4) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P5 (0x1u << 5) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P6 (0x1u << 6) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P7 (0x1u << 7) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P8 (0x1u << 8) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P9 (0x1u << 9) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P10 (0x1u << 10) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P11 (0x1u << 11) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P12 (0x1u << 12) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P13 (0x1u << 13) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P14 (0x1u << 14) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P15 (0x1u << 15) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P16 (0x1u << 16) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P17 (0x1u << 17) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P18 (0x1u << 18) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P19 (0x1u << 19) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P20 (0x1u << 20) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P21 (0x1u << 21) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P22 (0x1u << 22) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P23 (0x1u << 23) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P24 (0x1u << 24) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P25 (0x1u << 25) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P26 (0x1u << 26) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P27 (0x1u << 27) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P28 (0x1u << 28) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P29 (0x1u << 29) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P30 (0x1u << 30) /**< \brief (PIO_LOCKSR) Lock Status. */
#define PIO_LOCKSR_P31 (0x1u << 31) /**< \brief (PIO_LOCKSR) Lock Status. */
/* -------- PIO_WPMR : (PIO Offset: 0x00E4) Write Protect Mode Register -------- */
#define PIO_WPMR_WPEN (0x1u << 0) /**< \brief (PIO_WPMR) Write Protect Enable */
#define PIO_WPMR_WPKEY_Pos 8
#define PIO_WPMR_WPKEY_Msk (0xffffffu << PIO_WPMR_WPKEY_Pos) /**< \brief (PIO_WPMR) Write Protect KEY */
#define PIO_WPMR_WPKEY(value) ((PIO_WPMR_WPKEY_Msk & ((value) << PIO_WPMR_WPKEY_Pos)))
/* -------- PIO_WPSR : (PIO Offset: 0x00E8) Write Protect Status Register -------- */
#define PIO_WPSR_WPVS (0x1u << 0) /**< \brief (PIO_WPSR) Write Protect Violation Status */
#define PIO_WPSR_WPVSRC_Pos 8
#define PIO_WPSR_WPVSRC_Msk (0xffffu << PIO_WPSR_WPVSRC_Pos) /**< \brief (PIO_WPSR) Write Protect Violation Source */
/* -------- PIO_SCHMITT : (PIO Offset: 0x0100) Schmitt Trigger Register -------- */
#define PIO_SCHMITT_SCHMITT0 (0x1u << 0) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT1 (0x1u << 1) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT2 (0x1u << 2) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT3 (0x1u << 3) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT4 (0x1u << 4) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT5 (0x1u << 5) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT6 (0x1u << 6) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT7 (0x1u << 7) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT8 (0x1u << 8) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT9 (0x1u << 9) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT10 (0x1u << 10) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT11 (0x1u << 11) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT12 (0x1u << 12) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT13 (0x1u << 13) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT14 (0x1u << 14) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT15 (0x1u << 15) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT16 (0x1u << 16) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT17 (0x1u << 17) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT18 (0x1u << 18) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT19 (0x1u << 19) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT20 (0x1u << 20) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT21 (0x1u << 21) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT22 (0x1u << 22) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT23 (0x1u << 23) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT24 (0x1u << 24) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT25 (0x1u << 25) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT26 (0x1u << 26) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT27 (0x1u << 27) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT28 (0x1u << 28) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT29 (0x1u << 29) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT30 (0x1u << 30) /**< \brief (PIO_SCHMITT)  */
#define PIO_SCHMITT_SCHMITT31 (0x1u << 31) /**< \brief (PIO_SCHMITT)  */
/* -------- PIO_DELAYR : (PIO Offset: 0x0110) IO Delay Register -------- */
#define PIO_DELAYR_Delay0_Pos 0
#define PIO_DELAYR_Delay0_Msk (0xfu << PIO_DELAYR_Delay0_Pos) /**< \brief (PIO_DELAYR)  */
#define PIO_DELAYR_Delay0(value) ((PIO_DELAYR_Delay0_Msk & ((value) << PIO_DELAYR_Delay0_Pos)))
#define PIO_DELAYR_Delay1_Pos 4
#define PIO_DELAYR_Delay1_Msk (0xfu << PIO_DELAYR_Delay1_Pos) /**< \brief (PIO_DELAYR)  */
#define PIO_DELAYR_Delay1(value) ((PIO_DELAYR_Delay1_Msk & ((value) << PIO_DELAYR_Delay1_Pos)))
#define PIO_DELAYR_Delay2_Pos 8
#define PIO_DELAYR_Delay2_Msk (0xfu << PIO_DELAYR_Delay2_Pos) /**< \brief (PIO_DELAYR)  */
#define PIO_DELAYR_Delay2(value) ((PIO_DELAYR_Delay2_Msk & ((value) << PIO_DELAYR_Delay2_Pos)))
#define PIO_DELAYR_Delay3_Pos 12
#define PIO_DELAYR_Delay3_Msk (0xfu << PIO_DELAYR_Delay3_Pos) /**< \brief (PIO_DELAYR)  */
#define PIO_DELAYR_Delay3(value) ((PIO_DELAYR_Delay3_Msk & ((value) << PIO_DELAYR_Delay3_Pos)))
#define PIO_DELAYR_Delay4_Pos 16
#define PIO_DELAYR_Delay4_Msk (0xfu << PIO_DELAYR_Delay4_Pos) /**< \brief (PIO_DELAYR)  */
#define PIO_DELAYR_Delay4(value) ((PIO_DELAYR_Delay4_Msk & ((value) << PIO_DELAYR_Delay4_Pos)))
#define PIO_DELAYR_Delay5_Pos 20
#define PIO_DELAYR_Delay5_Msk (0xfu << PIO_DELAYR_Delay5_Pos) /**< \brief (PIO_DELAYR)  */
#define PIO_DELAYR_Delay5(value) ((PIO_DELAYR_Delay5_Msk & ((value) << PIO_DELAYR_Delay5_Pos)))
#define PIO_DELAYR_Delay6_Pos 24
#define PIO_DELAYR_Delay6_Msk (0xfu << PIO_DELAYR_Delay6_Pos) /**< \brief (PIO_DELAYR)  */
#define PIO_DELAYR_Delay6(value) ((PIO_DELAYR_Delay6_Msk & ((value) << PIO_DELAYR_Delay6_Pos)))
#define PIO_DELAYR_Delay7_Pos 28
#define PIO_DELAYR_Delay7_Msk (0xfu << PIO_DELAYR_Delay7_Pos) /**< \brief (PIO_DELAYR)  */
#define PIO_DELAYR_Delay7(value) ((PIO_DELAYR_Delay7_Msk & ((value) << PIO_DELAYR_Delay7_Pos)))
/* -------- PIO_DRIVER1 : (PIO Offset: 0x0114) I/O Drive Register 1 -------- */
#define PIO_DRIVER1_LINE0_Pos 0
#define PIO_DRIVER1_LINE0_Msk (0x3u << PIO_DRIVER1_LINE0_Pos) /**< \brief (PIO_DRIVER1) Drive of PIO line 0 */
#define   PIO_DRIVER1_LINE0_HI_DRIVE (0x0u << 0) /**< \brief (PIO_DRIVER1) High drive */
#define   PIO_DRIVER1_LINE0_ME_DRIVE (0x1u << 0) /**< \brief (PIO_DRIVER1) Medium drive */
#define   PIO_DRIVER1_LINE0_LO_DRIVE (0x2u << 0) /**< \brief (PIO_DRIVER1) Low drive */
#define PIO_DRIVER1_LINE1_Pos 2
#define PIO_DRIVER1_LINE1_Msk (0x3u << PIO_DRIVER1_LINE1_Pos) /**< \brief (PIO_DRIVER1) Drive of PIO line 1 */
#define   PIO_DRIVER1_LINE1_HI_DRIVE (0x0u << 2) /**< \brief (PIO_DRIVER1) High drive */
#define   PIO_DRIVER1_LINE1_ME_DRIVE (0x1u << 2) /**< \brief (PIO_DRIVER1) Medium drive */
#define   PIO_DRIVER1_LINE1_LO_DRIVE (0x2u << 2) /**< \brief (PIO_DRIVER1) Low drive */
#define PIO_DRIVER1_LINE2_Pos 4
#define PIO_DRIVER1_LINE2_Msk (0x3u << PIO_DRIVER1_LINE2_Pos) /**< \brief (PIO_DRIVER1) Drive of PIO line 2 */
#define   PIO_DRIVER1_LINE2_HI_DRIVE (0x0u << 4) /**< \brief (PIO_DRIVER1) High drive */
#define   PIO_DRIVER1_LINE2_ME_DRIVE (0x1u << 4) /**< \brief (PIO_DRIVER1) Medium drive */
#define   PIO_DRIVER1_LINE2_LO_DRIVE (0x2u << 4) /**< \brief (PIO_DRIVER1) Low drive */
#define PIO_DRIVER1_LINE3_Pos 6
#define PIO_DRIVER1_LINE3_Msk (0x3u << PIO_DRIVER1_LINE3_Pos) /**< \brief (PIO_DRIVER1) Drive of PIO line 3 */
#define   PIO_DRIVER1_LINE3_HI_DRIVE (0x0u << 6) /**< \brief (PIO_DRIVER1) High drive */
#define   PIO_DRIVER1_LINE3_ME_DRIVE (0x1u << 6) /**< \brief (PIO_DRIVER1) Medium drive */
#define   PIO_DRIVER1_LINE3_LO_DRIVE (0x2u << 6) /**< \brief (PIO_DRIVER1) Low drive */
#define PIO_DRIVER1_LINE4_Pos 8
#define PIO_DRIVER1_LINE4_Msk (0x3u << PIO_DRIVER1_LINE4_Pos) /**< \brief (PIO_DRIVER1) Drive of PIO line 4 */
#define   PIO_DRIVER1_LINE4_HI_DRIVE (0x0u << 8) /**< \brief (PIO_DRIVER1) High drive */
#define   PIO_DRIVER1_LINE4_ME_DRIVE (0x1u << 8) /**< \brief (PIO_DRIVER1) Medium drive */
#define   PIO_DRIVER1_LINE4_LO_DRIVE (0x2u << 8) /**< \brief (PIO_DRIVER1) Low drive */
#define PIO_DRIVER1_LINE5_Pos 10
#define PIO_DRIVER1_LINE5_Msk (0x3u << PIO_DRIVER1_LINE5_Pos) /**< \brief (PIO_DRIVER1) Drive of PIO line 5 */
#define   PIO_DRIVER1_LINE5_HI_DRIVE (0x0u << 10) /**< \brief (PIO_DRIVER1) High drive */
#define   PIO_DRIVER1_LINE5_ME_DRIVE (0x1u << 10) /**< \brief (PIO_DRIVER1) Medium drive */
#define   PIO_DRIVER1_LINE5_LO_DRIVE (0x2u << 10) /**< \brief (PIO_DRIVER1) Low drive */
#define PIO_DRIVER1_LINE6_Pos 12
#define PIO_DRIVER1_LINE6_Msk (0x3u << PIO_DRIVER1_LINE6_Pos) /**< \brief (PIO_DRIVER1) Drive of PIO line 6 */
#define   PIO_DRIVER1_LINE6_HI_DRIVE (0x0u << 12) /**< \brief (PIO_DRIVER1) High drive */
#define   PIO_DRIVER1_LINE6_ME_DRIVE (0x1u << 12) /**< \brief (PIO_DRIVER1) Medium drive */
#define   PIO_DRIVER1_LINE6_LO_DRIVE (0x2u << 12) /**< \brief (PIO_DRIVER1) Low drive */
#define PIO_DRIVER1_LINE7_Pos 14
#define PIO_DRIVER1_LINE7_Msk (0x3u << PIO_DRIVER1_LINE7_Pos) /**< \brief (PIO_DRIVER1) Drive of PIO line 7 */
#define   PIO_DRIVER1_LINE7_HI_DRIVE (0x0u << 14) /**< \brief (PIO_DRIVER1) High drive */
#define   PIO_DRIVER1_LINE7_ME_DRIVE (0x1u << 14) /**< \brief (PIO_DRIVER1) Medium drive */
#define   PIO_DRIVER1_LINE7_LO_DRIVE (0x2u << 14) /**< \brief (PIO_DRIVER1) Low drive */
#define PIO_DRIVER1_LINE8_Pos 16
#define PIO_DRIVER1_LINE8_Msk (0x3u << PIO_DRIVER1_LINE8_Pos) /**< \brief (PIO_DRIVER1) Drive of PIO line 8 */
#define   PIO_DRIVER1_LINE8_HI_DRIVE (0x0u << 16) /**< \brief (PIO_DRIVER1) High drive */
#define   PIO_DRIVER1_LINE8_ME_DRIVE (0x1u << 16) /**< \brief (PIO_DRIVER1) Medium drive */
#define   PIO_DRIVER1_LINE8_LO_DRIVE (0x2u << 16) /**< \brief (PIO_DRIVER1) Low drive */
#define PIO_DRIVER1_LINE9_Pos 18
#define PIO_DRIVER1_LINE9_Msk (0x3u << PIO_DRIVER1_LINE9_Pos) /**< \brief (PIO_DRIVER1) Drive of PIO line 9 */
#define   PIO_DRIVER1_LINE9_HI_DRIVE (0x0u << 18) /**< \brief (PIO_DRIVER1) High drive */
#define   PIO_DRIVER1_LINE9_ME_DRIVE (0x1u << 18) /**< \brief (PIO_DRIVER1) Medium drive */
#define   PIO_DRIVER1_LINE9_LO_DRIVE (0x2u << 18) /**< \brief (PIO_DRIVER1) Low drive */
#define PIO_DRIVER1_LINE10_Pos 20
#define PIO_DRIVER1_LINE10_Msk (0x3u << PIO_DRIVER1_LINE10_Pos) /**< \brief (PIO_DRIVER1) Drive of PIO line 10 */
#define   PIO_DRIVER1_LINE10_HI_DRIVE (0x0u << 20) /**< \brief (PIO_DRIVER1) High drive */
#define   PIO_DRIVER1_LINE10_ME_DRIVE (0x1u << 20) /**< \brief (PIO_DRIVER1) Medium drive */
#define   PIO_DRIVER1_LINE10_LO_DRIVE (0x2u << 20) /**< \brief (PIO_DRIVER1) Low drive */
#define PIO_DRIVER1_LINE11_Pos 22
#define PIO_DRIVER1_LINE11_Msk (0x3u << PIO_DRIVER1_LINE11_Pos) /**< \brief (PIO_DRIVER1) Drive of PIO line 11 */
#define   PIO_DRIVER1_LINE11_HI_DRIVE (0x0u << 22) /**< \brief (PIO_DRIVER1) High drive */
#define   PIO_DRIVER1_LINE11_ME_DRIVE (0x1u << 22) /**< \brief (PIO_DRIVER1) Medium drive */
#define   PIO_DRIVER1_LINE11_LO_DRIVE (0x2u << 22) /**< \brief (PIO_DRIVER1) Low drive */
#define PIO_DRIVER1_LINE12_Pos 24
#define PIO_DRIVER1_LINE12_Msk (0x3u << PIO_DRIVER1_LINE12_Pos) /**< \brief (PIO_DRIVER1) Drive of PIO line 12 */
#define   PIO_DRIVER1_LINE12_HI_DRIVE (0x0u << 24) /**< \brief (PIO_DRIVER1) High drive */
#define   PIO_DRIVER1_LINE12_ME_DRIVE (0x1u << 24) /**< \brief (PIO_DRIVER1) Medium drive */
#define   PIO_DRIVER1_LINE12_LO_DRIVE (0x2u << 24) /**< \brief (PIO_DRIVER1) Low drive */
#define PIO_DRIVER1_LINE13_Pos 26
#define PIO_DRIVER1_LINE13_Msk (0x3u << PIO_DRIVER1_LINE13_Pos) /**< \brief (PIO_DRIVER1) Drive of PIO line 13 */
#define   PIO_DRIVER1_LINE13_HI_DRIVE (0x0u << 26) /**< \brief (PIO_DRIVER1) High drive */
#define   PIO_DRIVER1_LINE13_ME_DRIVE (0x1u << 26) /**< \brief (PIO_DRIVER1) Medium drive */
#define   PIO_DRIVER1_LINE13_LO_DRIVE (0x2u << 26) /**< \brief (PIO_DRIVER1) Low drive */
#define PIO_DRIVER1_LINE14_Pos 28
#define PIO_DRIVER1_LINE14_Msk (0x3u << PIO_DRIVER1_LINE14_Pos) /**< \brief (PIO_DRIVER1) Drive of PIO line 14 */
#define   PIO_DRIVER1_LINE14_HI_DRIVE (0x0u << 28) /**< \brief (PIO_DRIVER1) High drive */
#define   PIO_DRIVER1_LINE14_ME_DRIVE (0x1u << 28) /**< \brief (PIO_DRIVER1) Medium drive */
#define   PIO_DRIVER1_LINE14_LO_DRIVE (0x2u << 28) /**< \brief (PIO_DRIVER1) Low drive */
#define PIO_DRIVER1_LINE15_Pos 30
#define PIO_DRIVER1_LINE15_Msk (0x3u << PIO_DRIVER1_LINE15_Pos) /**< \brief (PIO_DRIVER1) Drive of PIO line 15 */
#define   PIO_DRIVER1_LINE15_HI_DRIVE (0x0u << 30) /**< \brief (PIO_DRIVER1) High drive */
#define   PIO_DRIVER1_LINE15_ME_DRIVE (0x1u << 30) /**< \brief (PIO_DRIVER1) Medium drive */
#define   PIO_DRIVER1_LINE15_LO_DRIVE (0x2u << 30) /**< \brief (PIO_DRIVER1) Low drive */
/* -------- PIO_DRIVER2 : (PIO Offset: 0x0118) I/O Drive Register 2 -------- */
#define PIO_DRIVER2_LINE16_Pos 0
#define PIO_DRIVER2_LINE16_Msk (0x3u << PIO_DRIVER2_LINE16_Pos) /**< \brief (PIO_DRIVER2) Drive of PIO line 16 */
#define   PIO_DRIVER2_LINE16_HI_DRIVE (0x0u << 0) /**< \brief (PIO_DRIVER2) High drive */
#define   PIO_DRIVER2_LINE16_ME_DRIVE (0x1u << 0) /**< \brief (PIO_DRIVER2) Medium drive */
#define   PIO_DRIVER2_LINE16_LO_DRIVE (0x2u << 0) /**< \brief (PIO_DRIVER2) Low drive */
#define PIO_DRIVER2_LINE17_Pos 2
#define PIO_DRIVER2_LINE17_Msk (0x3u << PIO_DRIVER2_LINE17_Pos) /**< \brief (PIO_DRIVER2) Drive of PIO line 17 */
#define   PIO_DRIVER2_LINE17_HI_DRIVE (0x0u << 2) /**< \brief (PIO_DRIVER2) High drive */
#define   PIO_DRIVER2_LINE17_ME_DRIVE (0x1u << 2) /**< \brief (PIO_DRIVER2) Medium drive */
#define   PIO_DRIVER2_LINE17_LO_DRIVE (0x2u << 2) /**< \brief (PIO_DRIVER2) Low drive */
#define PIO_DRIVER2_LINE18_Pos 4
#define PIO_DRIVER2_LINE18_Msk (0x3u << PIO_DRIVER2_LINE18_Pos) /**< \brief (PIO_DRIVER2) Drive of PIO line 18 */
#define   PIO_DRIVER2_LINE18_HI_DRIVE (0x0u << 4) /**< \brief (PIO_DRIVER2) High drive */
#define   PIO_DRIVER2_LINE18_ME_DRIVE (0x1u << 4) /**< \brief (PIO_DRIVER2) Medium drive */
#define   PIO_DRIVER2_LINE18_LO_DRIVE (0x2u << 4) /**< \brief (PIO_DRIVER2) Low drive */
#define PIO_DRIVER2_LINE19_Pos 6
#define PIO_DRIVER2_LINE19_Msk (0x3u << PIO_DRIVER2_LINE19_Pos) /**< \brief (PIO_DRIVER2) Drive of PIO line 19 */
#define   PIO_DRIVER2_LINE19_HI_DRIVE (0x0u << 6) /**< \brief (PIO_DRIVER2) High drive */
#define   PIO_DRIVER2_LINE19_ME_DRIVE (0x1u << 6) /**< \brief (PIO_DRIVER2) Medium drive */
#define   PIO_DRIVER2_LINE19_LO_DRIVE (0x2u << 6) /**< \brief (PIO_DRIVER2) Low drive */
#define PIO_DRIVER2_LINE20_Pos 8
#define PIO_DRIVER2_LINE20_Msk (0x3u << PIO_DRIVER2_LINE20_Pos) /**< \brief (PIO_DRIVER2) Drive of PIO line 20 */
#define   PIO_DRIVER2_LINE20_HI_DRIVE (0x0u << 8) /**< \brief (PIO_DRIVER2) High drive */
#define   PIO_DRIVER2_LINE20_ME_DRIVE (0x1u << 8) /**< \brief (PIO_DRIVER2) Medium drive */
#define   PIO_DRIVER2_LINE20_LO_DRIVE (0x2u << 8) /**< \brief (PIO_DRIVER2) Low drive */
#define PIO_DRIVER2_LINE21_Pos 10
#define PIO_DRIVER2_LINE21_Msk (0x3u << PIO_DRIVER2_LINE21_Pos) /**< \brief (PIO_DRIVER2) Drive of PIO line 21 */
#define   PIO_DRIVER2_LINE21_HI_DRIVE (0x0u << 10) /**< \brief (PIO_DRIVER2) High drive */
#define   PIO_DRIVER2_LINE21_ME_DRIVE (0x1u << 10) /**< \brief (PIO_DRIVER2) Medium drive */
#define   PIO_DRIVER2_LINE21_LO_DRIVE (0x2u << 10) /**< \brief (PIO_DRIVER2) Low drive */
#define PIO_DRIVER2_LINE22_Pos 12
#define PIO_DRIVER2_LINE22_Msk (0x3u << PIO_DRIVER2_LINE22_Pos) /**< \brief (PIO_DRIVER2) Drive of PIO line 22 */
#define   PIO_DRIVER2_LINE22_HI_DRIVE (0x0u << 12) /**< \brief (PIO_DRIVER2) High drive */
#define   PIO_DRIVER2_LINE22_ME_DRIVE (0x1u << 12) /**< \brief (PIO_DRIVER2) Medium drive */
#define   PIO_DRIVER2_LINE22_LO_DRIVE (0x2u << 12) /**< \brief (PIO_DRIVER2) Low drive */
#define PIO_DRIVER2_LINE23_Pos 14
#define PIO_DRIVER2_LINE23_Msk (0x3u << PIO_DRIVER2_LINE23_Pos) /**< \brief (PIO_DRIVER2) Drive of PIO line 23 */
#define   PIO_DRIVER2_LINE23_HI_DRIVE (0x0u << 14) /**< \brief (PIO_DRIVER2) High drive */
#define   PIO_DRIVER2_LINE23_ME_DRIVE (0x1u << 14) /**< \brief (PIO_DRIVER2) Medium drive */
#define   PIO_DRIVER2_LINE23_LO_DRIVE (0x2u << 14) /**< \brief (PIO_DRIVER2) Low drive */
#define PIO_DRIVER2_LINE24_Pos 16
#define PIO_DRIVER2_LINE24_Msk (0x3u << PIO_DRIVER2_LINE24_Pos) /**< \brief (PIO_DRIVER2) Drive of PIO line 24 */
#define   PIO_DRIVER2_LINE24_HI_DRIVE (0x0u << 16) /**< \brief (PIO_DRIVER2) High drive */
#define   PIO_DRIVER2_LINE24_ME_DRIVE (0x1u << 16) /**< \brief (PIO_DRIVER2) Medium drive */
#define   PIO_DRIVER2_LINE24_LO_DRIVE (0x2u << 16) /**< \brief (PIO_DRIVER2) Low drive */
#define PIO_DRIVER2_LINE25_Pos 18
#define PIO_DRIVER2_LINE25_Msk (0x3u << PIO_DRIVER2_LINE25_Pos) /**< \brief (PIO_DRIVER2) Drive of PIO line 25 */
#define   PIO_DRIVER2_LINE25_HI_DRIVE (0x0u << 18) /**< \brief (PIO_DRIVER2) High drive */
#define   PIO_DRIVER2_LINE25_ME_DRIVE (0x1u << 18) /**< \brief (PIO_DRIVER2) Medium drive */
#define   PIO_DRIVER2_LINE25_LO_DRIVE (0x2u << 18) /**< \brief (PIO_DRIVER2) Low drive */
#define PIO_DRIVER2_LINE26_Pos 20
#define PIO_DRIVER2_LINE26_Msk (0x3u << PIO_DRIVER2_LINE26_Pos) /**< \brief (PIO_DRIVER2) Drive of PIO line 26 */
#define   PIO_DRIVER2_LINE26_HI_DRIVE (0x0u << 20) /**< \brief (PIO_DRIVER2) High drive */
#define   PIO_DRIVER2_LINE26_ME_DRIVE (0x1u << 20) /**< \brief (PIO_DRIVER2) Medium drive */
#define   PIO_DRIVER2_LINE26_LO_DRIVE (0x2u << 20) /**< \brief (PIO_DRIVER2) Low drive */
#define PIO_DRIVER2_LINE27_Pos 22
#define PIO_DRIVER2_LINE27_Msk (0x3u << PIO_DRIVER2_LINE27_Pos) /**< \brief (PIO_DRIVER2) Drive of PIO line 27 */
#define   PIO_DRIVER2_LINE27_HI_DRIVE (0x0u << 22) /**< \brief (PIO_DRIVER2) High drive */
#define   PIO_DRIVER2_LINE27_ME_DRIVE (0x1u << 22) /**< \brief (PIO_DRIVER2) Medium drive */
#define   PIO_DRIVER2_LINE27_LO_DRIVE (0x2u << 22) /**< \brief (PIO_DRIVER2) Low drive */
#define PIO_DRIVER2_LINE28_Pos 24
#define PIO_DRIVER2_LINE28_Msk (0x3u << PIO_DRIVER2_LINE28_Pos) /**< \brief (PIO_DRIVER2) Drive of PIO line 28 */
#define   PIO_DRIVER2_LINE28_HI_DRIVE (0x0u << 24) /**< \brief (PIO_DRIVER2) High drive */
#define   PIO_DRIVER2_LINE28_ME_DRIVE (0x1u << 24) /**< \brief (PIO_DRIVER2) Medium drive */
#define   PIO_DRIVER2_LINE28_LO_DRIVE (0x2u << 24) /**< \brief (PIO_DRIVER2) Low drive */
#define PIO_DRIVER2_LINE29_Pos 26
#define PIO_DRIVER2_LINE29_Msk (0x3u << PIO_DRIVER2_LINE29_Pos) /**< \brief (PIO_DRIVER2) Drive of PIO line 29 */
#define   PIO_DRIVER2_LINE29_HI_DRIVE (0x0u << 26) /**< \brief (PIO_DRIVER2) High drive */
#define   PIO_DRIVER2_LINE29_ME_DRIVE (0x1u << 26) /**< \brief (PIO_DRIVER2) Medium drive */
#define   PIO_DRIVER2_LINE29_LO_DRIVE (0x2u << 26) /**< \brief (PIO_DRIVER2) Low drive */
#define PIO_DRIVER2_LINE30_Pos 28
#define PIO_DRIVER2_LINE30_Msk (0x3u << PIO_DRIVER2_LINE30_Pos) /**< \brief (PIO_DRIVER2) Drive of PIO line 30 */
#define   PIO_DRIVER2_LINE30_HI_DRIVE (0x0u << 28) /**< \brief (PIO_DRIVER2) High drive */
#define   PIO_DRIVER2_LINE30_ME_DRIVE (0x1u << 28) /**< \brief (PIO_DRIVER2) Medium drive */
#define   PIO_DRIVER2_LINE30_LO_DRIVE (0x2u << 28) /**< \brief (PIO_DRIVER2) Low drive */
#define PIO_DRIVER2_LINE31_Pos 30
#define PIO_DRIVER2_LINE31_Msk (0x3u << PIO_DRIVER2_LINE31_Pos) /**< \brief (PIO_DRIVER2) Drive of PIO line 31 */
#define   PIO_DRIVER2_LINE31_HI_DRIVE (0x0u << 30) /**< \brief (PIO_DRIVER2) High drive */
#define   PIO_DRIVER2_LINE31_ME_DRIVE (0x1u << 30) /**< \brief (PIO_DRIVER2) Medium drive */
#define   PIO_DRIVER2_LINE31_LO_DRIVE (0x2u << 30) /**< \brief (PIO_DRIVER2) Low drive */

/*@}*/

/* ============================================================================= */
/**  SOFTWARE API DEFINITION FOR Periodic Interval Timer */
/* ============================================================================= */
/** \addtogroup SAM9N12_PIT Periodic Interval Timer */
/*@{*/

#ifndef __ASSEMBLY__
/** \brief Pit hardware registers */
typedef struct {
  RwReg PIT_MR;   /**< \brief (Pit Offset: 0x00) Mode Register */
  RoReg PIT_SR;   /**< \brief (Pit Offset: 0x04) Status Register */
  RoReg PIT_PIVR; /**< \brief (Pit Offset: 0x08) Periodic Interval Value Register */
  RoReg PIT_PIIR; /**< \brief (Pit Offset: 0x0C) Periodic Interval Image Register */
} Pit;
#endif /* __ASSEMBLY__ */
/* -------- PIT_MR : (PIT Offset: 0x00) Mode Register -------- */
#define PIT_MR_PIV_Pos 0
#define PIT_MR_PIV_Msk (0xfffffu << PIT_MR_PIV_Pos) /**< \brief (PIT_MR) Periodic Interval Value */
#define PIT_MR_PIV(value) ((PIT_MR_PIV_Msk & ((value) << PIT_MR_PIV_Pos)))
#define PIT_MR_PITEN (0x1u << 24) /**< \brief (PIT_MR) Period Interval Timer Enabled */
#define PIT_MR_PITIEN (0x1u << 25) /**< \brief (PIT_MR) Periodic Interval Timer Interrupt Enable */
/* -------- PIT_SR : (PIT Offset: 0x04) Status Register -------- */
#define PIT_SR_PITS (0x1u << 0) /**< \brief (PIT_SR) Periodic Interval Timer Status */
/* -------- PIT_PIVR : (PIT Offset: 0x08) Periodic Interval Value Register -------- */
#define PIT_PIVR_CPIV_Pos 0
#define PIT_PIVR_CPIV_Msk (0xfffffu << PIT_PIVR_CPIV_Pos) /**< \brief (PIT_PIVR) Current Periodic Interval Value */
#define PIT_PIVR_PICNT_Pos 20
#define PIT_PIVR_PICNT_Msk (0xfffu << PIT_PIVR_PICNT_Pos) /**< \brief (PIT_PIVR) Periodic Interval Counter */
/* -------- PIT_PIIR : (PIT Offset: 0x0C) Periodic Interval Image Register -------- */
#define PIT_PIIR_CPIV_Pos 0
#define PIT_PIIR_CPIV_Msk (0xfffffu << PIT_PIIR_CPIV_Pos) /**< \brief (PIT_PIIR) Current Periodic Interval Value */
#define PIT_PIIR_PICNT_Pos 20
#define PIT_PIIR_PICNT_Msk (0xfffu << PIT_PIIR_PICNT_Pos) /**< \brief (PIT_PIIR) Periodic Interval Counter */

/*@}*/

/* ============================================================================= */
/**  SOFTWARE API DEFINITION FOR Power Management Controller */
/* ============================================================================= */
/** \addtogroup SAM9N12_PMC Power Management Controller */
/*@{*/

#ifndef __ASSEMBLY__
/** \brief Pmc hardware registers */
typedef struct {
  WoReg PMC_SCER;      /**< \brief (Pmc Offset: 0x0000) System Clock Enable Register */
  WoReg PMC_SCDR;      /**< \brief (Pmc Offset: 0x0004) System Clock Disable Register */
  RoReg PMC_SCSR;      /**< \brief (Pmc Offset: 0x0008) System Clock Status Register */
  RoReg Reserved1[1];
  WoReg PMC_PCER;      /**< \brief (Pmc Offset: 0x0010) Peripheral Clock Enable Register */
  WoReg PMC_PCDR;      /**< \brief (Pmc Offset: 0x0014) Peripheral Clock Disable Register */
  RoReg PMC_PCSR;      /**< \brief (Pmc Offset: 0x0018) Peripheral Clock Status Register */
  RoReg Reserved2[1];
  RwReg CKGR_MOR;      /**< \brief (Pmc Offset: 0x0020) Main Oscillator Register */
  RwReg CKGR_MCFR;     /**< \brief (Pmc Offset: 0x0024) Main Clock Frequency Register */
  RwReg CKGR_PLLAR;    /**< \brief (Pmc Offset: 0x0028) PLLA Register */
  RwReg CKGR_PLLBR;    /**< \brief (Pmc Offset: 0x002C) PLLB Register */
  RwReg PMC_MCKR;      /**< \brief (Pmc Offset: 0x0030) Master Clock Register */
  RoReg Reserved3[1];
  RwReg PMC_USB;       /**< \brief (Pmc Offset: 0x0038) USB Clock Register */
  RoReg Reserved4[1];
  RwReg PMC_PCK[2];    /**< \brief (Pmc Offset: 0x0040) Programmable Clock 0 Register */
  RoReg Reserved5[6];
  WoReg PMC_IER;       /**< \brief (Pmc Offset: 0x0060) Interrupt Enable Register */
  WoReg PMC_IDR;       /**< \brief (Pmc Offset: 0x0064) Interrupt Disable Register */
  RoReg PMC_SR;        /**< \brief (Pmc Offset: 0x0068) Status Register */
  RoReg PMC_IMR;       /**< \brief (Pmc Offset: 0x006C) Interrupt Mask Register */
  RoReg Reserved6[4];
  WoReg PMC_PLLICPR;   /**< \brief (Pmc Offset: 0x0080) PLL Charge Pump Current Register */
  RoReg Reserved7[24];
  RwReg PMC_WPMR;      /**< \brief (Pmc Offset: 0x00E4) Write Protect Mode Register */
  RoReg PMC_WPSR;      /**< \brief (Pmc Offset: 0x00E8) Write Protect Status Register */
  RoReg Reserved8[8];
  RwReg PMC_PCR;       /**< \brief (Pmc Offset: 0x010C) Peripheral Control Register */
} Pmc;
#endif /* __ASSEMBLY__ */
/* -------- PMC_SCER : (PMC Offset: 0x0000) System Clock Enable Register -------- */
#define PMC_SCER_DDRCK (0x1u << 2) /**< \brief (PMC_SCER) DDR Clock Enable */
#define PMC_SCER_LCDCK (0x1u << 3) /**< \brief (PMC_SCER) LCD Clock Enable */
#define PMC_SCER_UHP (0x1u << 6) /**< \brief (PMC_SCER) USB Host OHCI Clocks Enable */
#define PMC_SCER_UDP (0x1u << 7) /**< \brief (PMC_SCER) USB Device Clock Enable */
#define PMC_SCER_PCK0 (0x1u << 8) /**< \brief (PMC_SCER) Programmable Clock 0 Output Enable */
#define PMC_SCER_PCK1 (0x1u << 9) /**< \brief (PMC_SCER) Programmable Clock 1 Output Enable */
/* -------- PMC_SCDR : (PMC Offset: 0x0004) System Clock Disable Register -------- */
#define PMC_SCDR_PCK (0x1u << 0) /**< \brief (PMC_SCDR) Processor Clock Disable */
#define PMC_SCDR_DDRCK (0x1u << 2) /**< \brief (PMC_SCDR) DDR Clock Disable */
#define PMC_SCDR_LCDCK (0x1u << 3) /**< \brief (PMC_SCDR) LCD Clock Disable */
#define PMC_SCDR_UHP (0x1u << 6) /**< \brief (PMC_SCDR) USB Host OHCI Clock Disable */
#define PMC_SCDR_UDP (0x1u << 7) /**< \brief (PMC_SCDR) USB Device Clock Enable */
#define PMC_SCDR_PCK0 (0x1u << 8) /**< \brief (PMC_SCDR) Programmable Clock 0 Output Disable */
#define PMC_SCDR_PCK1 (0x1u << 9) /**< \brief (PMC_SCDR) Programmable Clock 1 Output Disable */
/* -------- PMC_SCSR : (PMC Offset: 0x0008) System Clock Status Register -------- */
#define PMC_SCSR_PCK (0x1u << 0) /**< \brief (PMC_SCSR) Processor Clock Status */
#define PMC_SCSR_DDRCK (0x1u << 2) /**< \brief (PMC_SCSR) DDR Clock Status */
#define PMC_SCSR_LCDCK (0x1u << 3) /**< \brief (PMC_SCSR) LCD Clock Status */
#define PMC_SCSR_UHP (0x1u << 6) /**< \brief (PMC_SCSR) USB Host Port Clock Status */
#define PMC_SCSR_UDP (0x1u << 7) /**< \brief (PMC_SCSR) USB Device Port Clock Status */
#define PMC_SCSR_PCK0 (0x1u << 8) /**< \brief (PMC_SCSR) Programmable Clock 0 Output Status */
#define PMC_SCSR_PCK1 (0x1u << 9) /**< \brief (PMC_SCSR) Programmable Clock 1 Output Status */
/* -------- PMC_PCER : (PMC Offset: 0x0010) Peripheral Clock Enable Register -------- */
#define PMC_PCER_PID2 (0x1u << 2) /**< \brief (PMC_PCER) Peripheral Clock 2 Enable */
#define PMC_PCER_PID3 (0x1u << 3) /**< \brief (PMC_PCER) Peripheral Clock 3 Enable */
#define PMC_PCER_PID4 (0x1u << 4) /**< \brief (PMC_PCER) Peripheral Clock 4 Enable */
#define PMC_PCER_PID5 (0x1u << 5) /**< \brief (PMC_PCER) Peripheral Clock 5 Enable */
#define PMC_PCER_PID6 (0x1u << 6) /**< \brief (PMC_PCER) Peripheral Clock 6 Enable */
#define PMC_PCER_PID7 (0x1u << 7) /**< \brief (PMC_PCER) Peripheral Clock 7 Enable */
#define PMC_PCER_PID8 (0x1u << 8) /**< \brief (PMC_PCER) Peripheral Clock 8 Enable */
#define PMC_PCER_PID9 (0x1u << 9) /**< \brief (PMC_PCER) Peripheral Clock 9 Enable */
#define PMC_PCER_PID10 (0x1u << 10) /**< \brief (PMC_PCER) Peripheral Clock 10 Enable */
#define PMC_PCER_PID11 (0x1u << 11) /**< \brief (PMC_PCER) Peripheral Clock 11 Enable */
#define PMC_PCER_PID12 (0x1u << 12) /**< \brief (PMC_PCER) Peripheral Clock 12 Enable */
#define PMC_PCER_PID13 (0x1u << 13) /**< \brief (PMC_PCER) Peripheral Clock 13 Enable */
#define PMC_PCER_PID14 (0x1u << 14) /**< \brief (PMC_PCER) Peripheral Clock 14 Enable */
#define PMC_PCER_PID15 (0x1u << 15) /**< \brief (PMC_PCER) Peripheral Clock 15 Enable */
#define PMC_PCER_PID16 (0x1u << 16) /**< \brief (PMC_PCER) Peripheral Clock 16 Enable */
#define PMC_PCER_PID17 (0x1u << 17) /**< \brief (PMC_PCER) Peripheral Clock 17 Enable */
#define PMC_PCER_PID18 (0x1u << 18) /**< \brief (PMC_PCER) Peripheral Clock 18 Enable */
#define PMC_PCER_PID19 (0x1u << 19) /**< \brief (PMC_PCER) Peripheral Clock 19 Enable */
#define PMC_PCER_PID20 (0x1u << 20) /**< \brief (PMC_PCER) Peripheral Clock 20 Enable */
#define PMC_PCER_PID21 (0x1u << 21) /**< \brief (PMC_PCER) Peripheral Clock 21 Enable */
#define PMC_PCER_PID22 (0x1u << 22) /**< \brief (PMC_PCER) Peripheral Clock 22 Enable */
#define PMC_PCER_PID23 (0x1u << 23) /**< \brief (PMC_PCER) Peripheral Clock 23 Enable */
#define PMC_PCER_PID24 (0x1u << 24) /**< \brief (PMC_PCER) Peripheral Clock 24 Enable */
#define PMC_PCER_PID25 (0x1u << 25) /**< \brief (PMC_PCER) Peripheral Clock 25 Enable */
#define PMC_PCER_PID26 (0x1u << 26) /**< \brief (PMC_PCER) Peripheral Clock 26 Enable */
#define PMC_PCER_PID27 (0x1u << 27) /**< \brief (PMC_PCER) Peripheral Clock 27 Enable */
#define PMC_PCER_PID28 (0x1u << 28) /**< \brief (PMC_PCER) Peripheral Clock 28 Enable */
#define PMC_PCER_PID29 (0x1u << 29) /**< \brief (PMC_PCER) Peripheral Clock 29 Enable */
#define PMC_PCER_PID30 (0x1u << 30) /**< \brief (PMC_PCER) Peripheral Clock 30 Enable */
#define PMC_PCER_PID31 (0x1u << 31) /**< \brief (PMC_PCER) Peripheral Clock 31 Enable */
/* -------- PMC_PCDR : (PMC Offset: 0x0014) Peripheral Clock Disable Register -------- */
#define PMC_PCDR_PID2 (0x1u << 2) /**< \brief (PMC_PCDR) Peripheral Clock 2 Disable */
#define PMC_PCDR_PID3 (0x1u << 3) /**< \brief (PMC_PCDR) Peripheral Clock 3 Disable */
#define PMC_PCDR_PID4 (0x1u << 4) /**< \brief (PMC_PCDR) Peripheral Clock 4 Disable */
#define PMC_PCDR_PID5 (0x1u << 5) /**< \brief (PMC_PCDR) Peripheral Clock 5 Disable */
#define PMC_PCDR_PID6 (0x1u << 6) /**< \brief (PMC_PCDR) Peripheral Clock 6 Disable */
#define PMC_PCDR_PID7 (0x1u << 7) /**< \brief (PMC_PCDR) Peripheral Clock 7 Disable */
#define PMC_PCDR_PID8 (0x1u << 8) /**< \brief (PMC_PCDR) Peripheral Clock 8 Disable */
#define PMC_PCDR_PID9 (0x1u << 9) /**< \brief (PMC_PCDR) Peripheral Clock 9 Disable */
#define PMC_PCDR_PID10 (0x1u << 10) /**< \brief (PMC_PCDR) Peripheral Clock 10 Disable */
#define PMC_PCDR_PID11 (0x1u << 11) /**< \brief (PMC_PCDR) Peripheral Clock 11 Disable */
#define PMC_PCDR_PID12 (0x1u << 12) /**< \brief (PMC_PCDR) Peripheral Clock 12 Disable */
#define PMC_PCDR_PID13 (0x1u << 13) /**< \brief (PMC_PCDR) Peripheral Clock 13 Disable */
#define PMC_PCDR_PID14 (0x1u << 14) /**< \brief (PMC_PCDR) Peripheral Clock 14 Disable */
#define PMC_PCDR_PID15 (0x1u << 15) /**< \brief (PMC_PCDR) Peripheral Clock 15 Disable */
#define PMC_PCDR_PID16 (0x1u << 16) /**< \brief (PMC_PCDR) Peripheral Clock 16 Disable */
#define PMC_PCDR_PID17 (0x1u << 17) /**< \brief (PMC_PCDR) Peripheral Clock 17 Disable */
#define PMC_PCDR_PID18 (0x1u << 18) /**< \brief (PMC_PCDR) Peripheral Clock 18 Disable */
#define PMC_PCDR_PID19 (0x1u << 19) /**< \brief (PMC_PCDR) Peripheral Clock 19 Disable */
#define PMC_PCDR_PID20 (0x1u << 20) /**< \brief (PMC_PCDR) Peripheral Clock 20 Disable */
#define PMC_PCDR_PID21 (0x1u << 21) /**< \brief (PMC_PCDR) Peripheral Clock 21 Disable */
#define PMC_PCDR_PID22 (0x1u << 22) /**< \brief (PMC_PCDR) Peripheral Clock 22 Disable */
#define PMC_PCDR_PID23 (0x1u << 23) /**< \brief (PMC_PCDR) Peripheral Clock 23 Disable */
#define PMC_PCDR_PID24 (0x1u << 24) /**< \brief (PMC_PCDR) Peripheral Clock 24 Disable */
#define PMC_PCDR_PID25 (0x1u << 25) /**< \brief (PMC_PCDR) Peripheral Clock 25 Disable */
#define PMC_PCDR_PID26 (0x1u << 26) /**< \brief (PMC_PCDR) Peripheral Clock 26 Disable */
#define PMC_PCDR_PID27 (0x1u << 27) /**< \brief (PMC_PCDR) Peripheral Clock 27 Disable */
#define PMC_PCDR_PID28 (0x1u << 28) /**< \brief (PMC_PCDR) Peripheral Clock 28 Disable */
#define PMC_PCDR_PID29 (0x1u << 29) /**< \brief (PMC_PCDR) Peripheral Clock 29 Disable */
#define PMC_PCDR_PID30 (0x1u << 30) /**< \brief (PMC_PCDR) Peripheral Clock 30 Disable */
#define PMC_PCDR_PID31 (0x1u << 31) /**< \brief (PMC_PCDR) Peripheral Clock 31 Disable */
/* -------- PMC_PCSR : (PMC Offset: 0x0018) Peripheral Clock Status Register -------- */
#define PMC_PCSR_PID2 (0x1u << 2) /**< \brief (PMC_PCSR) Peripheral Clock 2 Status */
#define PMC_PCSR_PID3 (0x1u << 3) /**< \brief (PMC_PCSR) Peripheral Clock 3 Status */
#define PMC_PCSR_PID4 (0x1u << 4) /**< \brief (PMC_PCSR) Peripheral Clock 4 Status */
#define PMC_PCSR_PID5 (0x1u << 5) /**< \brief (PMC_PCSR) Peripheral Clock 5 Status */
#define PMC_PCSR_PID6 (0x1u << 6) /**< \brief (PMC_PCSR) Peripheral Clock 6 Status */
#define PMC_PCSR_PID7 (0x1u << 7) /**< \brief (PMC_PCSR) Peripheral Clock 7 Status */
#define PMC_PCSR_PID8 (0x1u << 8) /**< \brief (PMC_PCSR) Peripheral Clock 8 Status */
#define PMC_PCSR_PID9 (0x1u << 9) /**< \brief (PMC_PCSR) Peripheral Clock 9 Status */
#define PMC_PCSR_PID10 (0x1u << 10) /**< \brief (PMC_PCSR) Peripheral Clock 10 Status */
#define PMC_PCSR_PID11 (0x1u << 11) /**< \brief (PMC_PCSR) Peripheral Clock 11 Status */
#define PMC_PCSR_PID12 (0x1u << 12) /**< \brief (PMC_PCSR) Peripheral Clock 12 Status */
#define PMC_PCSR_PID13 (0x1u << 13) /**< \brief (PMC_PCSR) Peripheral Clock 13 Status */
#define PMC_PCSR_PID14 (0x1u << 14) /**< \brief (PMC_PCSR) Peripheral Clock 14 Status */
#define PMC_PCSR_PID15 (0x1u << 15) /**< \brief (PMC_PCSR) Peripheral Clock 15 Status */
#define PMC_PCSR_PID16 (0x1u << 16) /**< \brief (PMC_PCSR) Peripheral Clock 16 Status */
#define PMC_PCSR_PID17 (0x1u << 17) /**< \brief (PMC_PCSR) Peripheral Clock 17 Status */
#define PMC_PCSR_PID18 (0x1u << 18) /**< \brief (PMC_PCSR) Peripheral Clock 18 Status */
#define PMC_PCSR_PID19 (0x1u << 19) /**< \brief (PMC_PCSR) Peripheral Clock 19 Status */
#define PMC_PCSR_PID20 (0x1u << 20) /**< \brief (PMC_PCSR) Peripheral Clock 20 Status */
#define PMC_PCSR_PID21 (0x1u << 21) /**< \brief (PMC_PCSR) Peripheral Clock 21 Status */
#define PMC_PCSR_PID22 (0x1u << 22) /**< \brief (PMC_PCSR) Peripheral Clock 22 Status */
#define PMC_PCSR_PID23 (0x1u << 23) /**< \brief (PMC_PCSR) Peripheral Clock 23 Status */
#define PMC_PCSR_PID24 (0x1u << 24) /**< \brief (PMC_PCSR) Peripheral Clock 24 Status */
#define PMC_PCSR_PID25 (0x1u << 25) /**< \brief (PMC_PCSR) Peripheral Clock 25 Status */
#define PMC_PCSR_PID26 (0x1u << 26) /**< \brief (PMC_PCSR) Peripheral Clock 26 Status */
#define PMC_PCSR_PID27 (0x1u << 27) /**< \brief (PMC_PCSR) Peripheral Clock 27 Status */
#define PMC_PCSR_PID28 (0x1u << 28) /**< \brief (PMC_PCSR) Peripheral Clock 28 Status */
#define PMC_PCSR_PID29 (0x1u << 29) /**< \brief (PMC_PCSR) Peripheral Clock 29 Status */
#define PMC_PCSR_PID30 (0x1u << 30) /**< \brief (PMC_PCSR) Peripheral Clock 30 Status */
#define PMC_PCSR_PID31 (0x1u << 31) /**< \brief (PMC_PCSR) Peripheral Clock 31 Status */
/* -------- CKGR_MOR : (PMC Offset: 0x0020) Main Oscillator Register -------- */
#define CKGR_MOR_MOSCXTEN (0x1u << 0) /**< \brief (CKGR_MOR) Main Crystal Oscillator Enable */
#define CKGR_MOR_MOSCXTBY (0x1u << 1) /**< \brief (CKGR_MOR) Main Crystal Oscillator Bypass */
#define CKGR_MOR_MOSCRCEN (0x1u << 3) /**< \brief (CKGR_MOR) Main On-Chip RC Oscillator Enable */
#define CKGR_MOR_MOSCXTST_Pos 8
#define CKGR_MOR_MOSCXTST_Msk (0xffu << CKGR_MOR_MOSCXTST_Pos) /**< \brief (CKGR_MOR) Main Crystal Oscillator Start-up Time */
#define CKGR_MOR_MOSCXTST(value) ((CKGR_MOR_MOSCXTST_Msk & ((value) << CKGR_MOR_MOSCXTST_Pos)))
#define CKGR_MOR_KEY_Pos 16
#define CKGR_MOR_KEY_Msk (0xffu << CKGR_MOR_KEY_Pos) /**< \brief (CKGR_MOR) Password */
#define CKGR_MOR_KEY(value) ((CKGR_MOR_KEY_Msk & ((value) << CKGR_MOR_KEY_Pos)))
#define CKGR_MOR_MOSCSEL (0x1u << 24) /**< \brief (CKGR_MOR) Main Oscillator Selection */
#define CKGR_MOR_CFDEN (0x1u << 25) /**< \brief (CKGR_MOR) Clock Failure Detector Enable */
/* -------- CKGR_MCFR : (PMC Offset: 0x0024) Main Clock Frequency Register -------- */
#define CKGR_MCFR_MAINF_Pos 0
#define CKGR_MCFR_MAINF_Msk (0xffffu << CKGR_MCFR_MAINF_Pos) /**< \brief (CKGR_MCFR) Main Clock Frequency */
#define CKGR_MCFR_MAINF(value) ((CKGR_MCFR_MAINF_Msk & ((value) << CKGR_MCFR_MAINF_Pos)))
#define CKGR_MCFR_MAINFRDY (0x1u << 16) /**< \brief (CKGR_MCFR) Main Clock Ready */
#define CKGR_MCFR_RCMEAS (0x1u << 20) /**< \brief (CKGR_MCFR) RC Measure */
/* -------- CKGR_PLLAR : (PMC Offset: 0x0028) PLLA Register -------- */
#define CKGR_PLLAR_DIVA_Pos 0
#define CKGR_PLLAR_DIVA_Msk (0xffu << CKGR_PLLAR_DIVA_Pos) /**< \brief (CKGR_PLLAR) Divider A */
#define CKGR_PLLAR_DIVA(value) ((CKGR_PLLAR_DIVA_Msk & ((value) << CKGR_PLLAR_DIVA_Pos)))
#define CKGR_PLLAR_PLLACOUNT_Pos 8
#define CKGR_PLLAR_PLLACOUNT_Msk (0x3fu << CKGR_PLLAR_PLLACOUNT_Pos) /**< \brief (CKGR_PLLAR) PLLA Counter */
#define CKGR_PLLAR_PLLACOUNT(value) ((CKGR_PLLAR_PLLACOUNT_Msk & ((value) << CKGR_PLLAR_PLLACOUNT_Pos)))
#define CKGR_PLLAR_OUTA_Pos 14
#define CKGR_PLLAR_OUTA_Msk (0x3u << CKGR_PLLAR_OUTA_Pos) /**< \brief (CKGR_PLLAR) PLLA Clock Frequency Range */
#define CKGR_PLLAR_OUTA(value) ((CKGR_PLLAR_OUTA_Msk & ((value) << CKGR_PLLAR_OUTA_Pos)))
#define CKGR_PLLAR_MULA_Pos 16
#define CKGR_PLLAR_MULA_Msk (0x7ffu << CKGR_PLLAR_MULA_Pos) /**< \brief (CKGR_PLLAR) PLLA Multiplier */
#define CKGR_PLLAR_MULA(value) ((CKGR_PLLAR_MULA_Msk & ((value) << CKGR_PLLAR_MULA_Pos)))
#define CKGR_PLLAR_STUCKTO1 (0x1u << 29) /**< \brief (CKGR_PLLAR)  */
/* -------- CKGR_PLLBR : (PMC Offset: 0x002C) PLLB Register -------- */
#define CKGR_PLLBR_DIVB_Pos 0
#define CKGR_PLLBR_DIVB_Msk (0xffu << CKGR_PLLBR_DIVB_Pos) /**< \brief (CKGR_PLLBR) Divider B */
#define CKGR_PLLBR_DIVB(value) ((CKGR_PLLBR_DIVB_Msk & ((value) << CKGR_PLLBR_DIVB_Pos)))
#define CKGR_PLLBR_PLLBCOUNT_Pos 8
#define CKGR_PLLBR_PLLBCOUNT_Msk (0x3fu << CKGR_PLLBR_PLLBCOUNT_Pos) /**< \brief (CKGR_PLLBR) PLLB Counter */
#define CKGR_PLLBR_PLLBCOUNT(value) ((CKGR_PLLBR_PLLBCOUNT_Msk & ((value) << CKGR_PLLBR_PLLBCOUNT_Pos)))
#define CKGR_PLLBR_OUTB_Pos 14
#define CKGR_PLLBR_OUTB_Msk (0x3u << CKGR_PLLBR_OUTB_Pos) /**< \brief (CKGR_PLLBR) PLLB Clock Frequency Range */
#define CKGR_PLLBR_OUTB(value) ((CKGR_PLLBR_OUTB_Msk & ((value) << CKGR_PLLBR_OUTB_Pos)))
#define CKGR_PLLBR_MULB_Pos 16
#define CKGR_PLLBR_MULB_Msk (0x7ffu << CKGR_PLLBR_MULB_Pos) /**< \brief (CKGR_PLLBR) PLLB Multiplier */
#define CKGR_PLLBR_MULB(value) ((CKGR_PLLBR_MULB_Msk & ((value) << CKGR_PLLBR_MULB_Pos)))
/* -------- PMC_MCKR : (PMC Offset: 0x0030) Master Clock Register -------- */
#define PMC_MCKR_CSS_Pos 0
#define PMC_MCKR_CSS_Msk (0x3u << PMC_MCKR_CSS_Pos) /**< \brief (PMC_MCKR) Master/Processor Clock Source Selection */
#define   PMC_MCKR_CSS_SLOW_CLK (0x0u << 0) /**< \brief (PMC_MCKR) Slow Clock is selected */
#define   PMC_MCKR_CSS_MAIN_CLK (0x1u << 0) /**< \brief (PMC_MCKR) Main Clock is selected */
#define   PMC_MCKR_CSS_PLLA_CLK (0x2u << 0) /**< \brief (PMC_MCKR) PLLACK/PLLADIV2 is selected */
#define   PMC_MCKR_CSS_PLLB_CLK (0x3u << 0) /**< \brief (PMC_MCKR) PLLBCK is selected */
#define PMC_MCKR_PRES_Pos 4
#define PMC_MCKR_PRES_Msk (0x7u << PMC_MCKR_PRES_Pos) /**< \brief (PMC_MCKR) Master/Processor Clock Prescaler */
#define   PMC_MCKR_PRES_CLOCK_DIV1 (0x0u << 4) /**< \brief (PMC_MCKR) Selected clock */
#define   PMC_MCKR_PRES_CLOCK_DIV2 (0x1u << 4) /**< \brief (PMC_MCKR) Selected clock divided by 2 */
#define   PMC_MCKR_PRES_CLOCK_DIV4 (0x2u << 4) /**< \brief (PMC_MCKR) Selected clock divided by 4 */
#define   PMC_MCKR_PRES_CLOCK_DIV8 (0x3u << 4) /**< \brief (PMC_MCKR) Selected clock divided by 8 */
#define   PMC_MCKR_PRES_CLOCK_DIV16 (0x4u << 4) /**< \brief (PMC_MCKR) Selected clock divided by 16 */
#define   PMC_MCKR_PRES_CLOCK_DIV32 (0x5u << 4) /**< \brief (PMC_MCKR) Selected clock divided by 32 */
#define   PMC_MCKR_PRES_CLOCK_DIV64 (0x6u << 4) /**< \brief (PMC_MCKR) Selected clock divided by 64 */
#define PMC_MCKR_MDIV_Pos 8
#define PMC_MCKR_MDIV_Msk (0x3u << PMC_MCKR_MDIV_Pos) /**< \brief (PMC_MCKR) Master Clock Division */
#define   PMC_MCKR_MDIV_EQ_PCK (0x0u << 8) /**< \brief (PMC_MCKR) Master Clock is Prescaler Output Clock divided by 1.Warning: SysClk DDR and DDRCK are not available. */
#define   PMC_MCKR_MDIV_PCK_DIV2 (0x1u << 8) /**< \brief (PMC_MCKR) Master Clock is Prescaler Output Clock divided by 2.SysClk DDR is equal to 2 x MCK. DDRCK is equal to MCK. */
#define   PMC_MCKR_MDIV_PCK_DIV4 (0x2u << 8) /**< \brief (PMC_MCKR) Master Clock is Prescaler Output Clock divided by 4.SysClk DDR is equal to 2 x MCK. DDRCK is equal to MCK. */
#define   PMC_MCKR_MDIV_PCK_DIV3 (0x3u << 8) /**< \brief (PMC_MCKR) Master Clock is Prescaler Output Clock divided by 3.SysClk DDR is equal to 2 x MCK. DDRCK is equal to MCK. */
#define PMC_MCKR_PLLADIV2 (0x1u << 12) /**< \brief (PMC_MCKR) PLLA divisor by 2 */
#define   PMC_MCKR_PLLADIV2_NOT_DIV2 (0x0u << 12) /**< \brief (PMC_MCKR) PLLA clock frequency is divided by 1. */
#define   PMC_MCKR_PLLADIV2_DIV2 (0x1u << 12) /**< \brief (PMC_MCKR) PLLA clock frequency is divided by 2. */
/* -------- PMC_USB : (PMC Offset: 0x0038) USB Clock Register -------- */
#define PMC_USB_USBS (0x1u << 0) /**< \brief (PMC_USB) USB OHCI Input Clock Selection */
#define PMC_USB_USBDIV_Pos 8
#define PMC_USB_USBDIV_Msk (0xfu << PMC_USB_USBDIV_Pos) /**< \brief (PMC_USB) Divider for USB Clock */
#define PMC_USB_USBDIV(value) ((PMC_USB_USBDIV_Msk & ((value) << PMC_USB_USBDIV_Pos)))
/* -------- PMC_PCK[2] : (PMC Offset: 0x0040) Programmable Clock 0 Register -------- */
#define PMC_PCK_CSS_Pos 0
#define PMC_PCK_CSS_Msk (0x7u << PMC_PCK_CSS_Pos) /**< \brief (PMC_PCK[2]) Master Clock Source Selection */
#define   PMC_PCK_CSS_SLOW_CLK (0x0u << 0) /**< \brief (PMC_PCK[2]) Slow Clock is selected */
#define   PMC_PCK_CSS_MAIN_CLK (0x1u << 0) /**< \brief (PMC_PCK[2]) Main Clock is selected */
#define   PMC_PCK_CSS_PLLA_CLK (0x2u << 0) /**< \brief (PMC_PCK[2]) PLLACK/PLLADIV2 is selected */
#define   PMC_PCK_CSS_PLLB_CLK (0x3u << 0) /**< \brief (PMC_PCK[2]) PLLBCK is selected */
#define   PMC_PCK_CSS_MCK_CLK (0x4u << 0) /**< \brief (PMC_PCK[2]) Master Clock is selected */
#define PMC_PCK_PRES_Pos 4
#define PMC_PCK_PRES_Msk (0x7u << PMC_PCK_PRES_Pos) /**< \brief (PMC_PCK[2]) Programmable Clock Prescaler */
#define   PMC_PCK_PRES_CLOCK_DIV1 (0x0u << 4) /**< \brief (PMC_PCK[2]) Selected clock */
#define   PMC_PCK_PRES_CLOCK_DIV2 (0x1u << 4) /**< \brief (PMC_PCK[2]) Selected clock divided by 2 */
#define   PMC_PCK_PRES_CLOCK_DIV4 (0x2u << 4) /**< \brief (PMC_PCK[2]) Selected clock divided by 4 */
#define   PMC_PCK_PRES_CLOCK_DIV8 (0x3u << 4) /**< \brief (PMC_PCK[2]) Selected clock divided by 8 */
#define   PMC_PCK_PRES_CLOCK_DIV16 (0x4u << 4) /**< \brief (PMC_PCK[2]) Selected clock divided by 16 */
#define   PMC_PCK_PRES_CLOCK_DIV32 (0x5u << 4) /**< \brief (PMC_PCK[2]) Selected clock divided by 32 */
#define   PMC_PCK_PRES_CLOCK_DIV64 (0x6u << 4) /**< \brief (PMC_PCK[2]) Selected clock divided by 64 */
/* -------- PMC_IER : (PMC Offset: 0x0060) Interrupt Enable Register -------- */
#define PMC_IER_MOSCXTS (0x1u << 0) /**< \brief (PMC_IER) Main Crystal Oscillator Status Interrupt Enable */
#define PMC_IER_LOCKA (0x1u << 1) /**< \brief (PMC_IER) PLLA Lock Interrupt Enable */
#define PMC_IER_LOCKB (0x1u << 2) /**< \brief (PMC_IER) PLLB Lock Interrupt Enable */
#define PMC_IER_MCKRDY (0x1u << 3) /**< \brief (PMC_IER) Master Clock Ready Interrupt Enable */
#define PMC_IER_PCKRDY0 (0x1u << 8) /**< \brief (PMC_IER) Programmable Clock Ready 0 Interrupt Enable */
#define PMC_IER_PCKRDY1 (0x1u << 9) /**< \brief (PMC_IER) Programmable Clock Ready 1 Interrupt Enable */
#define PMC_IER_MOSCSELS (0x1u << 16) /**< \brief (PMC_IER) Main Oscillator Selection Status Interrupt Enable */
#define PMC_IER_MOSCRCS (0x1u << 17) /**< \brief (PMC_IER) Main On-Chip RC Status Interrupt Enable */
#define PMC_IER_CFDEV (0x1u << 18) /**< \brief (PMC_IER) Clock Failure Detector Event Interrupt Enable */
/* -------- PMC_IDR : (PMC Offset: 0x0064) Interrupt Disable Register -------- */
#define PMC_IDR_MOSCXTS (0x1u << 0) /**< \brief (PMC_IDR) Main Crystal Oscillator Status Interrupt Disable */
#define PMC_IDR_LOCKA (0x1u << 1) /**< \brief (PMC_IDR) PLLA Lock Interrupt Disable */
#define PMC_IDR_LOCKB (0x1u << 2) /**< \brief (PMC_IDR) PLLB Lock Interrupt Disable */
#define PMC_IDR_MCKRDY (0x1u << 3) /**< \brief (PMC_IDR) Master Clock Ready Interrupt Disable */
#define PMC_IDR_PCKRDY0 (0x1u << 8) /**< \brief (PMC_IDR) Programmable Clock Ready 0 Interrupt Disable */
#define PMC_IDR_PCKRDY1 (0x1u << 9) /**< \brief (PMC_IDR) Programmable Clock Ready 1 Interrupt Disable */
#define PMC_IDR_MOSCSELS (0x1u << 16) /**< \brief (PMC_IDR) Main Oscillator Selection Status Interrupt Disable */
#define PMC_IDR_MOSCRCS (0x1u << 17) /**< \brief (PMC_IDR) Main On-Chip RC Status Interrupt Disable */
#define PMC_IDR_CFDEV (0x1u << 18) /**< \brief (PMC_IDR) Clock Failure Detector Event Interrupt Disable */
/* -------- PMC_SR : (PMC Offset: 0x0068) Status Register -------- */
#define PMC_SR_MOSCXTS (0x1u << 0) /**< \brief (PMC_SR) Main XTAL Oscillator Status */
#define PMC_SR_LOCKA (0x1u << 1) /**< \brief (PMC_SR) PLLA Lock Status */
#define PMC_SR_LOCKB (0x1u << 2) /**< \brief (PMC_SR) PLLB Lock Status */
#define PMC_SR_MCKRDY (0x1u << 3) /**< \brief (PMC_SR) Master Clock Status */
#define PMC_SR_OSCSELS (0x1u << 7) /**< \brief (PMC_SR) Slow Clock Oscillator Selection */
#define PMC_SR_PCKRDY0 (0x1u << 8) /**< \brief (PMC_SR) Programmable Clock Ready Status */
#define PMC_SR_PCKRDY1 (0x1u << 9) /**< \brief (PMC_SR) Programmable Clock Ready Status */
#define PMC_SR_MOSCSELS (0x1u << 16) /**< \brief (PMC_SR) Main Oscillator Selection Status */
#define PMC_SR_MOSCRCS (0x1u << 17) /**< \brief (PMC_SR) Main On-Chip RC Oscillator Status */
#define PMC_SR_CFDEV (0x1u << 18) /**< \brief (PMC_SR) Clock Failure Detector Event */
#define PMC_SR_CFDS (0x1u << 19) /**< \brief (PMC_SR) Clock Failure Detector Status */
#define PMC_SR_FOS (0x1u << 20) /**< \brief (PMC_SR) Clock Failure Detector Fault Output Status */
/* -------- PMC_IMR : (PMC Offset: 0x006C) Interrupt Mask Register -------- */
#define PMC_IMR_MOSCXTS (0x1u << 0) /**< \brief (PMC_IMR) Main Crystal Oscillator Status Interrupt Mask */
#define PMC_IMR_LOCKA (0x1u << 1) /**< \brief (PMC_IMR) PLLA Lock Interrupt Mask */
#define PMC_IMR_LOCKB (0x1u << 2) /**< \brief (PMC_IMR) PLLB Lock Interrupt Mask */
#define PMC_IMR_MCKRDY (0x1u << 3) /**< \brief (PMC_IMR) Master Clock Ready Interrupt Mask */
#define PMC_IMR_PCKRDY0 (0x1u << 8) /**< \brief (PMC_IMR) Programmable Clock Ready 0 Interrupt Mask */
#define PMC_IMR_PCKRDY1 (0x1u << 9) /**< \brief (PMC_IMR) Programmable Clock Ready 1 Interrupt Mask */
#define PMC_IMR_MOSCSELS (0x1u << 16) /**< \brief (PMC_IMR) Main Oscillator Selection Status Interrupt Mask */
#define PMC_IMR_MOSCRCS (0x1u << 17) /**< \brief (PMC_IMR) Main On-Chip RC Status Interrupt Mask */
#define PMC_IMR_CFDEV (0x1u << 18) /**< \brief (PMC_IMR) Clock Failure Detector Event Interrupt Mask */
/* -------- PMC_PLLICPR : (PMC Offset: 0x0080) PLL Charge Pump Current Register -------- */
#define PMC_PLLICPR_ICPLLA (0x1u << 0) /**< \brief (PMC_PLLICPR) Charge Pump Current */
/* -------- PMC_WPMR : (PMC Offset: 0x00E4) Write Protect Mode Register -------- */
#define PMC_WPMR_WPEN (0x1u << 0) /**< \brief (PMC_WPMR) Write Protect Enable */
#define PMC_WPMR_WPKEY_Pos 8
#define PMC_WPMR_WPKEY_Msk (0xffffffu << PMC_WPMR_WPKEY_Pos) /**< \brief (PMC_WPMR) Write Protect KEY */
#define PMC_WPMR_WPKEY(value) ((PMC_WPMR_WPKEY_Msk & ((value) << PMC_WPMR_WPKEY_Pos)))
/* -------- PMC_WPSR : (PMC Offset: 0x00E8) Write Protect Status Register -------- */
#define PMC_WPSR_WPVS (0x1u << 0) /**< \brief (PMC_WPSR) Write Protect Violation Status */
#define PMC_WPSR_WPVSRC_Pos 8
#define PMC_WPSR_WPVSRC_Msk (0xffffu << PMC_WPSR_WPVSRC_Pos) /**< \brief (PMC_WPSR) Write Protect Violation Source */
/* -------- PMC_PCR : (PMC Offset: 0x010C) Peripheral Control Register -------- */
#define PMC_PCR_PID_Pos 0
#define PMC_PCR_PID_Msk (0x3fu << PMC_PCR_PID_Pos) /**< \brief (PMC_PCR) Peripheral ID */
#define PMC_PCR_PID(value) ((PMC_PCR_PID_Msk & ((value) << PMC_PCR_PID_Pos)))
#define PMC_PCR_CMD (0x1u << 12) /**< \brief (PMC_PCR) Command */
#define PMC_PCR_DIV_Pos 16
#define PMC_PCR_DIV_Msk (0x3u << PMC_PCR_DIV_Pos) /**< \brief (PMC_PCR) Divisor value */
#define   PMC_PCR_DIV_PERIPH_DIV_MCK (0x0u << 16) /**< \brief (PMC_PCR) Peripheral clock is MCK */
#define   PMC_PCR_DIV_PERIPH_DIV2_MCK (0x1u << 16) /**< \brief (PMC_PCR) Peripheral clock is MCK/2 */
#define   PMC_PCR_DIV_PERIPH_DIV4_MCK (0x2u << 16) /**< \brief (PMC_PCR) Peripheral clock is MCK/4 */
#define   PMC_PCR_DIV_PERIPH_DIV8_MCK (0x3u << 16) /**< \brief (PMC_PCR) Peripheral clock is MCK/8 */
#define PMC_PCR_EN (0x1u << 28) /**< \brief (PMC_PCR) Enable */

/*@}*/

/* ============================================================================= */
/**  SOFTWARE API DEFINITION FOR Error Corrected Code Controller */
/* ============================================================================= */
/** \addtogroup SAM9N12_PMECC Error Corrected Code Controller */
/*@{*/

#ifndef __ASSEMBLY__
/** \brief PmeccEcc hardware registers */
typedef struct {
  RwReg     PMECC_ECC[11]; /**< \brief (PmeccEcc Offset: 0x0) PMECC ECC x Register */
  RoReg     Reserved1[5];
} PmeccEcc;
/** \brief PmeccRem hardware registers */
typedef struct {
  RwReg     PMECC_REM[12]; /**< \brief (PmeccRem Offset: 0x0) PMECC REM x Register */
  RoReg     Reserved2[4];
} PmeccRem;
/** \brief Pmecc hardware registers */
#define PMECCECC_NUMBER 8
#define PMECCREM_NUMBER 8
typedef struct {
  RwReg     PMECC_CFG;    /**< \brief (Pmecc Offset: 0x00000000) PMECC Configuration Register */
  RwReg     PMECC_SAREA;  /**< \brief (Pmecc Offset: 0x00000004) PMECC Spare Area Size Register */
  RwReg     PMECC_SADDR;  /**< \brief (Pmecc Offset: 0x00000008) PMECC Start Address Register */
  RwReg     PMECC_EADDR;  /**< \brief (Pmecc Offset: 0x0000000C) PMECC End Address Register */
  RwReg     PMECC_CLK;    /**< \brief (Pmecc Offset: 0x00000010) PMECC Clock Control Register */
  WoReg     PMECC_CTRL;   /**< \brief (Pmecc Offset: 0x00000014) PMECC Control Register */
  RoReg     PMECC_SR;     /**< \brief (Pmecc Offset: 0x00000018) PMECC Status Register */
  WoReg     PMECC_IER;    /**< \brief (Pmecc Offset: 0x0000001C) PMECC Interrupt Enable register */
  WoReg     PMECC_IDR;    /**< \brief (Pmecc Offset: 0x00000020) PMECC Interrupt Disable Register */
  RoReg     PMECC_IMR;    /**< \brief (Pmecc Offset: 0x00000024) PMECC Interrupt Mask Register */
  RoReg     PMECC_ISR;    /**< \brief (Pmecc Offset: 0x00000028) PMECC Interrupt Status Register */
  RoReg     Reserved1[5];
  PmeccEcc  PMECC_ECC[PMECCECC_NUMBER]; /**< \brief (Pmecc Offset: 0x40) sec_num = 0 .. 7 */
  PmeccRem  PMECC_REM[PMECCREM_NUMBER]; /**< \brief (Pmecc Offset: 0x240) sec_num = 0 .. 7 */
} Pmecc;
#endif /* __ASSEMBLY__ */
/* -------- PMECC_CFG : (PMECC Offset: 0x00000000) PMECC Configuration Register -------- */
#define PMECC_CFG_BCH_ERR_Pos 0
#define PMECC_CFG_BCH_ERR_Msk (0x7u << PMECC_CFG_BCH_ERR_Pos) /**< \brief (PMECC_CFG) Error Correct Capability */
#define   PMECC_CFG_BCH_ERR_BCH_ERR2 (0x0u << 0) /**< \brief (PMECC_CFG) 2 errors */
#define   PMECC_CFG_BCH_ERR_BCH_ERR4 (0x1u << 0) /**< \brief (PMECC_CFG) 4 errors */
#define   PMECC_CFG_BCH_ERR_BCH_ERR8 (0x2u << 0) /**< \brief (PMECC_CFG) 8 errors */
#define   PMECC_CFG_BCH_ERR_BCH_ERR12 (0x3u << 0) /**< \brief (PMECC_CFG) 12 errors */
#define   PMECC_CFG_BCH_ERR_BCH_ERR24 (0x4u << 0) /**< \brief (PMECC_CFG) 24 errors */
#define PMECC_CFG_SECTORSZ (0x1u << 4) /**< \brief (PMECC_CFG) Sector Size */
#define PMECC_CFG_PAGESIZE_Pos 8
#define PMECC_CFG_PAGESIZE_Msk (0x3u << PMECC_CFG_PAGESIZE_Pos) /**< \brief (PMECC_CFG) Number of Sectors in the Page */
#define   PMECC_CFG_PAGESIZE_PAGESIZE_1SEC (0x0u << 8) /**< \brief (PMECC_CFG) 1 sector for main area (512 or 1024 bytes) */
#define   PMECC_CFG_PAGESIZE_PAGESIZE_2SEC (0x1u << 8) /**< \brief (PMECC_CFG) 2 sectors for main area (1024 or 2048 bytes) */
#define   PMECC_CFG_PAGESIZE_PAGESIZE_4SEC (0x2u << 8) /**< \brief (PMECC_CFG) 4 sectors for main area (2048 or 4096 bytes) */
#define   PMECC_CFG_PAGESIZE_PAGESIZE_8SEC (0x3u << 8) /**< \brief (PMECC_CFG) 8 errors for main area (4096 or 8192 bytes) */
#define PMECC_CFG_NANDWR (0x1u << 12) /**< \brief (PMECC_CFG) NAND Write Access */
#define PMECC_CFG_SPAREEN (0x1u << 16) /**< \brief (PMECC_CFG) Spare Enable */
#define PMECC_CFG_AUTO (0x1u << 20) /**< \brief (PMECC_CFG) Automatic Mode Enable */
/* -------- PMECC_SAREA : (PMECC Offset: 0x00000004) PMECC Spare Area Size Register -------- */
#define PMECC_SAREA_SPARESIZE_Pos 0
#define PMECC_SAREA_SPARESIZE_Msk (0x1ffu << PMECC_SAREA_SPARESIZE_Pos) /**< \brief (PMECC_SAREA) Spare Area Size */
#define PMECC_SAREA_SPARESIZE(value) ((PMECC_SAREA_SPARESIZE_Msk & ((value) << PMECC_SAREA_SPARESIZE_Pos)))
/* -------- PMECC_SADDR : (PMECC Offset: 0x00000008) PMECC Start Address Register -------- */
#define PMECC_SADDR_STARTADDR_Pos 0
#define PMECC_SADDR_STARTADDR_Msk (0x1ffu << PMECC_SADDR_STARTADDR_Pos) /**< \brief (PMECC_SADDR) ECC Area Start Address (byte oriented address) */
#define PMECC_SADDR_STARTADDR(value) ((PMECC_SADDR_STARTADDR_Msk & ((value) << PMECC_SADDR_STARTADDR_Pos)))
/* -------- PMECC_EADDR : (PMECC Offset: 0x0000000C) PMECC End Address Register -------- */
#define PMECC_EADDR_ENDADDR_Pos 0
#define PMECC_EADDR_ENDADDR_Msk (0x1ffu << PMECC_EADDR_ENDADDR_Pos) /**< \brief (PMECC_EADDR) ECC Area End Address (byte oriented address) */
#define PMECC_EADDR_ENDADDR(value) ((PMECC_EADDR_ENDADDR_Msk & ((value) << PMECC_EADDR_ENDADDR_Pos)))
/* -------- PMECC_CLK : (PMECC Offset: 0x00000010) PMECC Clock Control Register -------- */
#define PMECC_CLK_CLKCTRL_Pos 0
#define PMECC_CLK_CLKCTRL_Msk (0x7u << PMECC_CLK_CLKCTRL_Pos) /**< \brief (PMECC_CLK) Clock Control Register */
#define PMECC_CLK_CLKCTRL(value) ((PMECC_CLK_CLKCTRL_Msk & ((value) << PMECC_CLK_CLKCTRL_Pos)))
/* -------- PMECC_CTRL : (PMECC Offset: 0x00000014) PMECC Control Register -------- */
#define PMECC_CTRL_RST (0x1u << 0) /**< \brief (PMECC_CTRL) Reset the PMECC Module */
#define PMECC_CTRL_DATA (0x1u << 1) /**< \brief (PMECC_CTRL) Start a Data Phase */
#define PMECC_CTRL_USER (0x1u << 2) /**< \brief (PMECC_CTRL) Start a User Mode Phase */
#define PMECC_CTRL_ENABLE (0x1u << 4) /**< \brief (PMECC_CTRL) PMECC Module Enable */
#define PMECC_CTRL_DISABLE (0x1u << 5) /**< \brief (PMECC_CTRL) PMECC Module Disable */
/* -------- PMECC_SR : (PMECC Offset: 0x00000018) PMECC Status Register -------- */
#define PMECC_SR_BUSY (0x1u << 0) /**< \brief (PMECC_SR) The Kernel of the PMECC is Busy */
#define PMECC_SR_ENABLE (0x1u << 4) /**< \brief (PMECC_SR) PMECC Module Status */
/* -------- PMECC_IER : (PMECC Offset: 0x0000001C) PMECC Interrupt Enable register -------- */
#define PMECC_IER_ERRIE (0x1u << 0) /**< \brief (PMECC_IER) Error Interrupt Enable */
/* -------- PMECC_IDR : (PMECC Offset: 0x00000020) PMECC Interrupt Disable Register -------- */
#define PMECC_IDR_ERRID (0x1u << 0) /**< \brief (PMECC_IDR) Error Interrupt Disable */
/* -------- PMECC_IMR : (PMECC Offset: 0x00000024) PMECC Interrupt Mask Register -------- */
#define PMECC_IMR_ERRIM (0x1u << 0) /**< \brief (PMECC_IMR) Error Interrupt Enable */
/* -------- PMECC_ISR : (PMECC Offset: 0x00000028) PMECC Interrupt Status Register -------- */
#define PMECC_ISR_ERRIS_Pos 0
#define PMECC_ISR_ERRIS_Msk (0xffu << PMECC_ISR_ERRIS_Pos) /**< \brief (PMECC_ISR) Error Interrupt Status Register */
/* -------- PMECC_ECC[11] : (PMECC Offset: N/A) PMECC ECC x Register -------- */
#define PMECC_ECC_ECC_Pos 0
#define PMECC_ECC_ECC_Msk (0xffffffffu << PMECC_ECC_ECC_Pos) /**< \brief (PMECC_ECC[11]) BCH Redundancy */
/* -------- PMECC_REM[12] : (PMECC Offset: N/A) PMECC REM x Register -------- */
#define PMECC_REM_REM2NP1_Pos 0
#define PMECC_REM_REM2NP1_Msk (0x3fffu << PMECC_REM_REM2NP1_Pos) /**< \brief (PMECC_REM[12]) BCH Remainder 2 * N + 1 */
#define PMECC_REM_REM2NP3_Pos 16
#define PMECC_REM_REM2NP3_Msk (0x3fffu << PMECC_REM_REM2NP3_Pos) /**< \brief (PMECC_REM[12]) BCH Remainder 2 * N + 3 */

/*@}*/

/* ============================================================================= */
/**  SOFTWARE API DEFINITION FOR Programmable Multibit ECC Error Location */
/* ============================================================================= */
/** \addtogroup SAM9N12_PMERRLOC Programmable Multibit ECC Error Location */
/*@{*/

#ifndef __ASSEMBLY__
/** \brief Pmerrloc hardware registers */
typedef struct {
  RwReg PMERRLOC_ELCFG;     /**< \brief (Pmerrloc Offset: 0x000) Error Location Configuration Register */
  RoReg PMERRLOC_ELPRIM;    /**< \brief (Pmerrloc Offset: 0x004) Error Location Primitive Register */
  RwReg PMERRLOC_ELEN;      /**< \brief (Pmerrloc Offset: 0x008) Error Location Enable Register */
  RwReg PMERRLOC_ELDIS;     /**< \brief (Pmerrloc Offset: 0x00C) Error Location Disable Register */
  RwReg PMERRLOC_ELSR;      /**< \brief (Pmerrloc Offset: 0x010) Error Location Status Register */
  RoReg PMERRLOC_ELIER;     /**< \brief (Pmerrloc Offset: 0x014) Error Location Interrupt Enable register */
  RoReg PMERRLOC_ELIDR;     /**< \brief (Pmerrloc Offset: 0x018) Error Location Interrupt Disable Register */
  RoReg PMERRLOC_ELIMR;     /**< \brief (Pmerrloc Offset: 0x01C) Error Location Interrupt Mask Register */
  RoReg PMERRLOC_ELISR;     /**< \brief (Pmerrloc Offset: 0x020) Error Location Interrupt Status Register */
  RoReg Reserved1[1];
  RwReg PMERRLOC_SIGMA[25]; /**< \brief (Pmerrloc Offset: 0x028) PMECC SIGMA 0 Register */
  RoReg PMERRLOC_EL[24];    /**< \brief (Pmerrloc Offset: 0x08C) PMECC Error Location 0 Register */
} Pmerrloc;
#endif /* __ASSEMBLY__ */
/* -------- PMERRLOC_ELCFG : (PMERRLOC Offset: 0x000) Error Location Configuration Register -------- */
#define PMERRLOC_ELCFG_SECTORSZ (0x1u << 0) /**< \brief (PMERRLOC_ELCFG) Sector Size */
#define PMERRLOC_ELCFG_ERRNUM_Pos 16
#define PMERRLOC_ELCFG_ERRNUM_Msk (0x1fu << PMERRLOC_ELCFG_ERRNUM_Pos) /**< \brief (PMERRLOC_ELCFG) Number of Errors */
#define PMERRLOC_ELCFG_ERRNUM(value) ((PMERRLOC_ELCFG_ERRNUM_Msk & ((value) << PMERRLOC_ELCFG_ERRNUM_Pos)))
/* -------- PMERRLOC_ELPRIM : (PMERRLOC Offset: 0x004) Error Location Primitive Register -------- */
#define PMERRLOC_ELPRIM_PRIMITIV_Pos 0
#define PMERRLOC_ELPRIM_PRIMITIV_Msk (0xffffu << PMERRLOC_ELPRIM_PRIMITIV_Pos) /**< \brief (PMERRLOC_ELPRIM) Primitive Polynomial */
/* -------- PMERRLOC_ELEN : (PMERRLOC Offset: 0x008) Error Location Enable Register -------- */
#define PMERRLOC_ELEN_ENINIT_Pos 0
#define PMERRLOC_ELEN_ENINIT_Msk (0x3fffu << PMERRLOC_ELEN_ENINIT_Pos) /**< \brief (PMERRLOC_ELEN) Initial Number of Bits in the Codeword */
#define PMERRLOC_ELEN_ENINIT(value) ((PMERRLOC_ELEN_ENINIT_Msk & ((value) << PMERRLOC_ELEN_ENINIT_Pos)))
/* -------- PMERRLOC_ELDIS : (PMERRLOC Offset: 0x00C) Error Location Disable Register -------- */
#define PMERRLOC_ELDIS_DIS (0x1u << 0) /**< \brief (PMERRLOC_ELDIS) Disable Error Location Engine */
/* -------- PMERRLOC_ELSR : (PMERRLOC Offset: 0x010) Error Location Status Register -------- */
#define PMERRLOC_ELSR_BUSY (0x1u << 0) /**< \brief (PMERRLOC_ELSR) Error Location Engine Busy */
/* -------- PMERRLOC_ELIER : (PMERRLOC Offset: 0x014) Error Location Interrupt Enable register -------- */
#define PMERRLOC_ELIER_DONE (0x1u << 0) /**< \brief (PMERRLOC_ELIER) Computation Terminated Interrupt Enable */
/* -------- PMERRLOC_ELIDR : (PMERRLOC Offset: 0x018) Error Location Interrupt Disable Register -------- */
#define PMERRLOC_ELIDR_DONE (0x1u << 0) /**< \brief (PMERRLOC_ELIDR) Computation Terminated Interrupt Disable */
/* -------- PMERRLOC_ELIMR : (PMERRLOC Offset: 0x01C) Error Location Interrupt Mask Register -------- */
#define PMERRLOC_ELIMR_DONE (0x1u << 0) /**< \brief (PMERRLOC_ELIMR) Computation Terminated Interrupt Mask */
/* -------- PMERRLOC_ELISR : (PMERRLOC Offset: 0x020) Error Location Interrupt Status Register -------- */
#define PMERRLOC_ELISR_DONE (0x1u << 0) /**< \brief (PMERRLOC_ELISR) Computation Terminated Interrupt Status */
#define PMERRLOC_ELISR_ERR_CNT_Pos 8
#define PMERRLOC_ELISR_ERR_CNT_Msk (0x1fu << PMERRLOC_ELISR_ERR_CNT_Pos) /**< \brief (PMERRLOC_ELISR) Error Counter value */
/* -------- PMERRLOC_SIGMA[25] : (PMERRLOC Offset: 0x028) PMECC SIGMA 0 Register -------- */
#define PMERRLOC_SIGMA_SIGMAN_Pos 0
#define PMERRLOC_SIGMA_SIGMAN_Msk (0x3fffu << PMERRLOC_SIGMA_SIGMAN_Pos) /**< \brief (PMERRLOC_SIGMA[25])  */
#define PMERRLOC_SIGMA_SIGMAN(value) ((PMERRLOC_SIGMA_SIGMAN_Msk & ((value) << PMERRLOC_SIGMA_SIGMAN_Pos)))
/* -------- PMERRLOC_EL[24] : (PMERRLOC Offset: 0x08C) PMECC Error Location 0 Register -------- */
#define PMERRLOC_EL_ERRLOCN_Pos 0
#define PMERRLOC_EL_ERRLOCN_Msk (0x3fffu << PMERRLOC_EL_ERRLOCN_Pos) /**< \brief (PMERRLOC_EL[24]) Error Position within the set {sector area, spare area}. */

/*@}*/

/* ============================================================================= */
/**  SOFTWARE API DEFINITION FOR Reset Controller */
/* ============================================================================= */
/** \addtogroup SAM9N12_RSTC Reset Controller */
/*@{*/

#ifndef __ASSEMBLY__
/** \brief Rstc hardware registers */
typedef struct {
  WoReg RSTC_CR; /**< \brief (Rstc Offset: 0x00) Control Register */
  RoReg RSTC_SR; /**< \brief (Rstc Offset: 0x04) Status Register */
  RwReg RSTC_MR; /**< \brief (Rstc Offset: 0x08) Mode Register */
} Rstc;
#endif /* __ASSEMBLY__ */
/* -------- RSTC_CR : (RSTC Offset: 0x00) Control Register -------- */
#define RSTC_CR_PROCRST (0x1u << 0) /**< \brief (RSTC_CR) Processor Reset */
#define RSTC_CR_PERRST (0x1u << 2) /**< \brief (RSTC_CR) Peripheral Reset */
#define RSTC_CR_EXTRST (0x1u << 3) /**< \brief (RSTC_CR) External Reset */
#define RSTC_CR_KEY_Pos 24
#define RSTC_CR_KEY_Msk (0xffu << RSTC_CR_KEY_Pos) /**< \brief (RSTC_CR) Password */
#define RSTC_CR_KEY(value) ((RSTC_CR_KEY_Msk & ((value) << RSTC_CR_KEY_Pos)))
/* -------- RSTC_SR : (RSTC Offset: 0x04) Status Register -------- */
#define RSTC_SR_URSTS (0x1u << 0) /**< \brief (RSTC_SR) User Reset Status */
#define RSTC_SR_RSTTYP_Pos 8
#define RSTC_SR_RSTTYP_Msk (0x7u << RSTC_SR_RSTTYP_Pos) /**< \brief (RSTC_SR) Reset Type */
#define RSTC_SR_NRSTL (0x1u << 16) /**< \brief (RSTC_SR) NRST Pin Level */
#define RSTC_SR_SRCMP (0x1u << 17) /**< \brief (RSTC_SR) Software Reset Command in Progress */
/* -------- RSTC_MR : (RSTC Offset: 0x08) Mode Register -------- */
#define RSTC_MR_ERSTL_Pos 8
#define RSTC_MR_ERSTL_Msk (0xfu << RSTC_MR_ERSTL_Pos) /**< \brief (RSTC_MR) External Reset Length */
#define RSTC_MR_ERSTL(value) ((RSTC_MR_ERSTL_Msk & ((value) << RSTC_MR_ERSTL_Pos)))
#define RSTC_MR_KEY_Pos 24
#define RSTC_MR_KEY_Msk (0xffu << RSTC_MR_KEY_Pos) /**< \brief (RSTC_MR) Password */
#define RSTC_MR_KEY(value) ((RSTC_MR_KEY_Msk & ((value) << RSTC_MR_KEY_Pos)))

/*@}*/

/* ============================================================================= */
/**  SOFTWARE API DEFINITION FOR Static Memory Controller */
/* ============================================================================= */
/** \addtogroup SAM9N12_SMC Static Memory Controller */
/*@{*/

#ifndef __ASSEMBLY__
/** \brief SmcCs_number hardware registers */
typedef struct {
  RwReg         SMC_SETUP;        /**< \brief (SmcCs_number Offset: 0x0) SMC Setup Register */
  RwReg         SMC_PULSE;        /**< \brief (SmcCs_number Offset: 0x4) SMC Pulse Register */
  RwReg         SMC_CYCLE;        /**< \brief (SmcCs_number Offset: 0x8) SMC Cycle Register */
  RwReg         SMC_MODE;         /**< \brief (SmcCs_number Offset: 0xC) SMC Mode Register */
} SmcCs_number;
/** \brief Smc hardware registers */
#define SMCCS_NUMBER_NUMBER 6
typedef struct {
  SmcCs_number  SMC_CS_NUMBER[SMCCS_NUMBER_NUMBER]; /**< \brief (Smc Offset: 0x0) CS_number = 0 .. 5 */
  RoReg         Reserved1[24];
  RwReg         SMC_DELAY1;       /**< \brief (Smc Offset: 0xC0) SMC Delay on I/O */
  RwReg         SMC_DELAY2;       /**< \brief (Smc Offset: 0xC4) SMC Delay on I/O */
  RwReg         SMC_DELAY3;       /**< \brief (Smc Offset: 0xC8) SMC Delay on I/O */
  RwReg         SMC_DELAY4;       /**< \brief (Smc Offset: 0xCC) SMC Delay on I/O */
  RwReg         SMC_DELAY5;       /**< \brief (Smc Offset: 0xD0) SMC Delay on I/O */
  RwReg         SMC_DELAY6;       /**< \brief (Smc Offset: 0xD4) SMC Delay on I/O */
  RwReg         SMC_DELAY7;       /**< \brief (Smc Offset: 0xD8) SMC Delay on I/O */
  RwReg         SMC_DELAY8;       /**< \brief (Smc Offset: 0xDC) SMC Delay on I/O */
  RoReg         Reserved2[1];
  RwReg         SMC_WPMR;         /**< \brief (Smc Offset: 0xE4) SMC Write Protect Mode Register */
  RoReg         SMC_WPSR;         /**< \brief (Smc Offset: 0xE8) SMC Write Protect Status Register */
} Smc;
#endif /* __ASSEMBLY__ */
/* -------- SMC_SETUP : (SMC Offset: N/A) SMC Setup Register -------- */
#define SMC_SETUP_NWE_SETUP_Pos 0
#define SMC_SETUP_NWE_SETUP_Msk (0x3fu << SMC_SETUP_NWE_SETUP_Pos) /**< \brief (SMC_SETUP) NWE Setup Length */
#define SMC_SETUP_NWE_SETUP(value) ((SMC_SETUP_NWE_SETUP_Msk & ((value) << SMC_SETUP_NWE_SETUP_Pos)))
#define SMC_SETUP_NCS_WR_SETUP_Pos 8
#define SMC_SETUP_NCS_WR_SETUP_Msk (0x3fu << SMC_SETUP_NCS_WR_SETUP_Pos) /**< \brief (SMC_SETUP) NCS Setup Length in WRITE Access */
#define SMC_SETUP_NCS_WR_SETUP(value) ((SMC_SETUP_NCS_WR_SETUP_Msk & ((value) << SMC_SETUP_NCS_WR_SETUP_Pos)))
#define SMC_SETUP_NRD_SETUP_Pos 16
#define SMC_SETUP_NRD_SETUP_Msk (0x3fu << SMC_SETUP_NRD_SETUP_Pos) /**< \brief (SMC_SETUP) NRD Setup Length */
#define SMC_SETUP_NRD_SETUP(value) ((SMC_SETUP_NRD_SETUP_Msk & ((value) << SMC_SETUP_NRD_SETUP_Pos)))
#define SMC_SETUP_NCS_RD_SETUP_Pos 24
#define SMC_SETUP_NCS_RD_SETUP_Msk (0x3fu << SMC_SETUP_NCS_RD_SETUP_Pos) /**< \brief (SMC_SETUP) NCS Setup Length in READ Access */
#define SMC_SETUP_NCS_RD_SETUP(value) ((SMC_SETUP_NCS_RD_SETUP_Msk & ((value) << SMC_SETUP_NCS_RD_SETUP_Pos)))
/* -------- SMC_PULSE : (SMC Offset: N/A) SMC Pulse Register -------- */
#define SMC_PULSE_NWE_PULSE_Pos 0
#define SMC_PULSE_NWE_PULSE_Msk (0x7fu << SMC_PULSE_NWE_PULSE_Pos) /**< \brief (SMC_PULSE) NWE Pulse Length */
#define SMC_PULSE_NWE_PULSE(value) ((SMC_PULSE_NWE_PULSE_Msk & ((value) << SMC_PULSE_NWE_PULSE_Pos)))
#define SMC_PULSE_NCS_WR_PULSE_Pos 8
#define SMC_PULSE_NCS_WR_PULSE_Msk (0x7fu << SMC_PULSE_NCS_WR_PULSE_Pos) /**< \brief (SMC_PULSE) NCS Pulse Length in WRITE Access */
#define SMC_PULSE_NCS_WR_PULSE(value) ((SMC_PULSE_NCS_WR_PULSE_Msk & ((value) << SMC_PULSE_NCS_WR_PULSE_Pos)))
#define SMC_PULSE_NRD_PULSE_Pos 16
#define SMC_PULSE_NRD_PULSE_Msk (0x7fu << SMC_PULSE_NRD_PULSE_Pos) /**< \brief (SMC_PULSE) NRD Pulse Length */
#define SMC_PULSE_NRD_PULSE(value) ((SMC_PULSE_NRD_PULSE_Msk & ((value) << SMC_PULSE_NRD_PULSE_Pos)))
#define SMC_PULSE_NCS_RD_PULSE_Pos 24
#define SMC_PULSE_NCS_RD_PULSE_Msk (0x7fu << SMC_PULSE_NCS_RD_PULSE_Pos) /**< \brief (SMC_PULSE) NCS Pulse Length in READ Access */
#define SMC_PULSE_NCS_RD_PULSE(value) ((SMC_PULSE_NCS_RD_PULSE_Msk & ((value) << SMC_PULSE_NCS_RD_PULSE_Pos)))
/* -------- SMC_CYCLE : (SMC Offset: N/A) SMC Cycle Register -------- */
#define SMC_CYCLE_NWE_CYCLE_Pos 0
#define SMC_CYCLE_NWE_CYCLE_Msk (0x1ffu << SMC_CYCLE_NWE_CYCLE_Pos) /**< \brief (SMC_CYCLE) Total Write Cycle Length */
#define SMC_CYCLE_NWE_CYCLE(value) ((SMC_CYCLE_NWE_CYCLE_Msk & ((value) << SMC_CYCLE_NWE_CYCLE_Pos)))
#define SMC_CYCLE_NRD_CYCLE_Pos 16
#define SMC_CYCLE_NRD_CYCLE_Msk (0x1ffu << SMC_CYCLE_NRD_CYCLE_Pos) /**< \brief (SMC_CYCLE) Total Read Cycle Length */
#define SMC_CYCLE_NRD_CYCLE(value) ((SMC_CYCLE_NRD_CYCLE_Msk & ((value) << SMC_CYCLE_NRD_CYCLE_Pos)))
/* -------- SMC_MODE : (SMC Offset: N/A) SMC Mode Register -------- */
#define SMC_MODE_READ_MODE (0x1u << 0) /**< \brief (SMC_MODE)  */
#define SMC_MODE_WRITE_MODE (0x1u << 1) /**< \brief (SMC_MODE)  */
#define SMC_MODE_EXNW_MODE_Pos 4
#define SMC_MODE_EXNW_MODE_Msk (0x3u << SMC_MODE_EXNW_MODE_Pos) /**< \brief (SMC_MODE) NWAIT Mode */
#define SMC_MODE_EXNW_MODE(value) ((SMC_MODE_EXNW_MODE_Msk & ((value) << SMC_MODE_EXNW_MODE_Pos)))
#define SMC_MODE_BAT (0x1u << 8) /**< \brief (SMC_MODE) Byte Access Type */
#define SMC_MODE_DBW_Pos 12
#define SMC_MODE_DBW_Msk (0x3u << SMC_MODE_DBW_Pos) /**< \brief (SMC_MODE) Data Bus Width */
#define SMC_MODE_DBW(value) ((SMC_MODE_DBW_Msk & ((value) << SMC_MODE_DBW_Pos)))
#define SMC_MODE_TDF_CYCLES_Pos 16
#define SMC_MODE_TDF_CYCLES_Msk (0xfu << SMC_MODE_TDF_CYCLES_Pos) /**< \brief (SMC_MODE) Data Float Time */
#define SMC_MODE_TDF_CYCLES(value) ((SMC_MODE_TDF_CYCLES_Msk & ((value) << SMC_MODE_TDF_CYCLES_Pos)))
#define SMC_MODE_TDF_MODE (0x1u << 20) /**< \brief (SMC_MODE) TDF Optimization */
#define SMC_MODE_PMEN (0x1u << 24) /**< \brief (SMC_MODE) Page Mode Enabled */
#define SMC_MODE_PS_Pos 28
#define SMC_MODE_PS_Msk (0x3u << SMC_MODE_PS_Pos) /**< \brief (SMC_MODE) Page Size */
#define SMC_MODE_PS(value) ((SMC_MODE_PS_Msk & ((value) << SMC_MODE_PS_Pos)))
/* -------- SMC_DELAY1 : (SMC Offset: 0xC0) SMC Delay on I/O -------- */
#define SMC_DELAY1_Delay1_Pos 0
#define SMC_DELAY1_Delay1_Msk (0xfu << SMC_DELAY1_Delay1_Pos) /**< \brief (SMC_DELAY1)  */
#define SMC_DELAY1_Delay1(value) ((SMC_DELAY1_Delay1_Msk & ((value) << SMC_DELAY1_Delay1_Pos)))
#define SMC_DELAY1_Delay2_Pos 4
#define SMC_DELAY1_Delay2_Msk (0xfu << SMC_DELAY1_Delay2_Pos) /**< \brief (SMC_DELAY1)  */
#define SMC_DELAY1_Delay2(value) ((SMC_DELAY1_Delay2_Msk & ((value) << SMC_DELAY1_Delay2_Pos)))
#define SMC_DELAY1_Delay3_Pos 8
#define SMC_DELAY1_Delay3_Msk (0xfu << SMC_DELAY1_Delay3_Pos) /**< \brief (SMC_DELAY1)  */
#define SMC_DELAY1_Delay3(value) ((SMC_DELAY1_Delay3_Msk & ((value) << SMC_DELAY1_Delay3_Pos)))
#define SMC_DELAY1_Delay4_Pos 12
#define SMC_DELAY1_Delay4_Msk (0xfu << SMC_DELAY1_Delay4_Pos) /**< \brief (SMC_DELAY1)  */
#define SMC_DELAY1_Delay4(value) ((SMC_DELAY1_Delay4_Msk & ((value) << SMC_DELAY1_Delay4_Pos)))
#define SMC_DELAY1_Delay5_Pos 16
#define SMC_DELAY1_Delay5_Msk (0xfu << SMC_DELAY1_Delay5_Pos) /**< \brief (SMC_DELAY1)  */
#define SMC_DELAY1_Delay5(value) ((SMC_DELAY1_Delay5_Msk & ((value) << SMC_DELAY1_Delay5_Pos)))
#define SMC_DELAY1_Delay6_Pos 20
#define SMC_DELAY1_Delay6_Msk (0xfu << SMC_DELAY1_Delay6_Pos) /**< \brief (SMC_DELAY1)  */
#define SMC_DELAY1_Delay6(value) ((SMC_DELAY1_Delay6_Msk & ((value) << SMC_DELAY1_Delay6_Pos)))
#define SMC_DELAY1_Delay7_Pos 24
#define SMC_DELAY1_Delay7_Msk (0xfu << SMC_DELAY1_Delay7_Pos) /**< \brief (SMC_DELAY1)  */
#define SMC_DELAY1_Delay7(value) ((SMC_DELAY1_Delay7_Msk & ((value) << SMC_DELAY1_Delay7_Pos)))
#define SMC_DELAY1_Delay8_Pos 28
#define SMC_DELAY1_Delay8_Msk (0xfu << SMC_DELAY1_Delay8_Pos) /**< \brief (SMC_DELAY1)  */
#define SMC_DELAY1_Delay8(value) ((SMC_DELAY1_Delay8_Msk & ((value) << SMC_DELAY1_Delay8_Pos)))
/* -------- SMC_WPMR : (SMC Offset: 0xE4) SMC Write Protect Mode Register -------- */
#define SMC_WPMR_WPEN (0x1u << 0) /**< \brief (SMC_WPMR) Write Protect Enable */
#define SMC_WPMR_WPKEY_Pos 8
#define SMC_WPMR_WPKEY_Msk (0xffffffu << SMC_WPMR_WPKEY_Pos) /**< \brief (SMC_WPMR) Write Protect KEY */
#define SMC_WPMR_WPKEY(value) ((SMC_WPMR_WPKEY_Msk & ((value) << SMC_WPMR_WPKEY_Pos)))
/* -------- SMC_WPSR : (SMC Offset: 0xE8) SMC Write Protect Status Register -------- */
#define SMC_WPSR_WPVS (0x1u << 0) /**< \brief (SMC_WPSR) Write Protect Enable */
#define SMC_WPSR_WPVSRC_Pos 8
#define SMC_WPSR_WPVSRC_Msk (0xffffu << SMC_WPSR_WPVSRC_Pos) /**< \brief (SMC_WPSR) Write Protect Violation Source */

/*@}*/

/* ============================================================================= */
/**  SOFTWARE API DEFINITION FOR Serial Peripheral Interface */
/* ============================================================================= */
/** \addtogroup SAM9N12_SPI Serial Peripheral Interface */
/*@{*/

#ifndef __ASSEMBLY__
/** \brief Spi hardware registers */
typedef struct {
  WoReg SPI_CR;        /**< \brief (Spi Offset: 0x00) Control Register */
  RwReg SPI_MR;        /**< \brief (Spi Offset: 0x04) Mode Register */
  RoReg SPI_RDR;       /**< \brief (Spi Offset: 0x08) Receive Data Register */
  WoReg SPI_TDR;       /**< \brief (Spi Offset: 0x0C) Transmit Data Register */
  RoReg SPI_SR;        /**< \brief (Spi Offset: 0x10) Status Register */
  WoReg SPI_IER;       /**< \brief (Spi Offset: 0x14) Interrupt Enable Register */
  WoReg SPI_IDR;       /**< \brief (Spi Offset: 0x18) Interrupt Disable Register */
  RoReg SPI_IMR;       /**< \brief (Spi Offset: 0x1C) Interrupt Mask Register */
  RoReg Reserved1[4];
  RwReg SPI_CSR[4];    /**< \brief (Spi Offset: 0x30) Chip Select Register */
  RoReg Reserved2[41];
  RwReg SPI_WPMR;      /**< \brief (Spi Offset: 0xE4) Write Protection Control Register */
  RoReg SPI_WPSR;      /**< \brief (Spi Offset: 0xE8) Write Protection Status Register */
} Spi;
#endif /* __ASSEMBLY__ */
/* -------- SPI_CR : (SPI Offset: 0x00) Control Register -------- */
#define SPI_CR_SPIEN (0x1u << 0) /**< \brief (SPI_CR) SPI Enable */
#define SPI_CR_SPIDIS (0x1u << 1) /**< \brief (SPI_CR) SPI Disable */
#define SPI_CR_SWRST (0x1u << 7) /**< \brief (SPI_CR) SPI Software Reset */
#define SPI_CR_LASTXFER (0x1u << 24) /**< \brief (SPI_CR) Last Transfer */
/* -------- SPI_MR : (SPI Offset: 0x04) Mode Register -------- */
#define SPI_MR_MSTR (0x1u << 0) /**< \brief (SPI_MR) Master/Slave Mode */
#define SPI_MR_PS (0x1u << 1) /**< \brief (SPI_MR) Peripheral Select */
#define SPI_MR_PCSDEC (0x1u << 2) /**< \brief (SPI_MR) Chip Select Decode */
#define SPI_MR_MODFDIS (0x1u << 4) /**< \brief (SPI_MR) Mode Fault Detection */
#define SPI_MR_WDRBT (0x1u << 5) /**< \brief (SPI_MR) Wait Data Read Before Transfer */
#define SPI_MR_LLB (0x1u << 7) /**< \brief (SPI_MR) Local Loopback Enable */
#define SPI_MR_PCS_Pos 16
#define SPI_MR_PCS_Msk (0xfu << SPI_MR_PCS_Pos) /**< \brief (SPI_MR) Peripheral Chip Select */
#define SPI_MR_PCS(value) ((SPI_MR_PCS_Msk & ((value) << SPI_MR_PCS_Pos)))
#define SPI_MR_DLYBCS_Pos 24
#define SPI_MR_DLYBCS_Msk (0xffu << SPI_MR_DLYBCS_Pos) /**< \brief (SPI_MR) Delay Between Chip Selects */
#define SPI_MR_DLYBCS(value) ((SPI_MR_DLYBCS_Msk & ((value) << SPI_MR_DLYBCS_Pos)))
/* -------- SPI_RDR : (SPI Offset: 0x08) Receive Data Register -------- */
#define SPI_RDR_RD_Pos 0
#define SPI_RDR_RD_Msk (0xffffu << SPI_RDR_RD_Pos) /**< \brief (SPI_RDR) Receive Data */
#define SPI_RDR_PCS_Pos 16
#define SPI_RDR_PCS_Msk (0xfu << SPI_RDR_PCS_Pos) /**< \brief (SPI_RDR) Peripheral Chip Select */
/* -------- SPI_TDR : (SPI Offset: 0x0C) Transmit Data Register -------- */
#define SPI_TDR_TD_Pos 0
#define SPI_TDR_TD_Msk (0xffffu << SPI_TDR_TD_Pos) /**< \brief (SPI_TDR) Transmit Data */
#define SPI_TDR_TD(value) ((SPI_TDR_TD_Msk & ((value) << SPI_TDR_TD_Pos)))
#define SPI_TDR_PCS_Pos 16
#define SPI_TDR_PCS_Msk (0xfu << SPI_TDR_PCS_Pos) /**< \brief (SPI_TDR) Peripheral Chip Select */
#define SPI_TDR_PCS(value) ((SPI_TDR_PCS_Msk & ((value) << SPI_TDR_PCS_Pos)))
#define SPI_TDR_LASTXFER (0x1u << 24) /**< \brief (SPI_TDR) Last Transfer */
/* -------- SPI_SR : (SPI Offset: 0x10) Status Register -------- */
#define SPI_SR_RDRF (0x1u << 0) /**< \brief (SPI_SR) Receive Data Register Full */
#define SPI_SR_TDRE (0x1u << 1) /**< \brief (SPI_SR) Transmit Data Register Empty */
#define SPI_SR_MODF (0x1u << 2) /**< \brief (SPI_SR) Mode Fault Error */
#define SPI_SR_OVRES (0x1u << 3) /**< \brief (SPI_SR) Overrun Error Status */
#define SPI_SR_NSSR (0x1u << 8) /**< \brief (SPI_SR) NSS Rising */
#define SPI_SR_TXEMPTY (0x1u << 9) /**< \brief (SPI_SR) Transmission Registers Empty */
#define SPI_SR_SPIENS (0x1u << 16) /**< \brief (SPI_SR) SPI Enable Status */
/* -------- SPI_IER : (SPI Offset: 0x14) Interrupt Enable Register -------- */
#define SPI_IER_RDRF (0x1u << 0) /**< \brief (SPI_IER) Receive Data Register Full Interrupt Enable */
#define SPI_IER_TDRE (0x1u << 1) /**< \brief (SPI_IER) SPI Transmit Data Register Empty Interrupt Enable */
#define SPI_IER_MODF (0x1u << 2) /**< \brief (SPI_IER) Mode Fault Error Interrupt Enable */
#define SPI_IER_OVRES (0x1u << 3) /**< \brief (SPI_IER) Overrun Error Interrupt Enable */
#define SPI_IER_NSSR (0x1u << 8) /**< \brief (SPI_IER) NSS Rising Interrupt Enable */
#define SPI_IER_TXEMPTY (0x1u << 9) /**< \brief (SPI_IER) Transmission Registers Empty Enable */
/* -------- SPI_IDR : (SPI Offset: 0x18) Interrupt Disable Register -------- */
#define SPI_IDR_RDRF (0x1u << 0) /**< \brief (SPI_IDR) Receive Data Register Full Interrupt Disable */
#define SPI_IDR_TDRE (0x1u << 1) /**< \brief (SPI_IDR) SPI Transmit Data Register Empty Interrupt Disable */
#define SPI_IDR_MODF (0x1u << 2) /**< \brief (SPI_IDR) Mode Fault Error Interrupt Disable */
#define SPI_IDR_OVRES (0x1u << 3) /**< \brief (SPI_IDR) Overrun Error Interrupt Disable */
#define SPI_IDR_NSSR (0x1u << 8) /**< \brief (SPI_IDR) NSS Rising Interrupt Disable */
#define SPI_IDR_TXEMPTY (0x1u << 9) /**< \brief (SPI_IDR) Transmission Registers Empty Disable */
/* -------- SPI_IMR : (SPI Offset: 0x1C) Interrupt Mask Register -------- */
#define SPI_IMR_RDRF (0x1u << 0) /**< \brief (SPI_IMR) Receive Data Register Full Interrupt Mask */
#define SPI_IMR_TDRE (0x1u << 1) /**< \brief (SPI_IMR) SPI Transmit Data Register Empty Interrupt Mask */
#define SPI_IMR_MODF (0x1u << 2) /**< \brief (SPI_IMR) Mode Fault Error Interrupt Mask */
#define SPI_IMR_OVRES (0x1u << 3) /**< \brief (SPI_IMR) Overrun Error Interrupt Mask */
#define SPI_IMR_NSSR (0x1u << 8) /**< \brief (SPI_IMR) NSS Rising Interrupt Mask */
#define SPI_IMR_TXEMPTY (0x1u << 9) /**< \brief (SPI_IMR) Transmission Registers Empty Mask */
/* -------- SPI_CSR[4] : (SPI Offset: 0x30) Chip Select Register -------- */
#define SPI_CSR_CPOL (0x1u << 0) /**< \brief (SPI_CSR[4]) Clock Polarity */
#define SPI_CSR_NCPHA (0x1u << 1) /**< \brief (SPI_CSR[4]) Clock Phase */
#define SPI_CSR_CSNAAT (0x1u << 2) /**< \brief (SPI_CSR[4]) Chip Select Not Active After Transfer (Ignored if CSAAT = 1) */
#define SPI_CSR_CSAAT (0x1u << 3) /**< \brief (SPI_CSR[4]) Chip Select Not Active After Transfer (Ignored if CSAAT = 1) */
#define SPI_CSR_BITS_Pos 4
#define SPI_CSR_BITS_Msk (0xfu << SPI_CSR_BITS_Pos) /**< \brief (SPI_CSR[4]) Bits Per Transfer */
#define   SPI_CSR_BITS_8_BIT (0x0u << 4) /**< \brief (SPI_CSR[4]) 8 bits for transfer */
#define   SPI_CSR_BITS_9_BIT (0x1u << 4) /**< \brief (SPI_CSR[4]) 9 bits for transfer */
#define   SPI_CSR_BITS_10_BIT (0x2u << 4) /**< \brief (SPI_CSR[4]) 10 bits for transfer */
#define   SPI_CSR_BITS_11_BIT (0x3u << 4) /**< \brief (SPI_CSR[4]) 11 bits for transfer */
#define   SPI_CSR_BITS_12_BIT (0x4u << 4) /**< \brief (SPI_CSR[4]) 12 bits for transfer */
#define   SPI_CSR_BITS_13_BIT (0x5u << 4) /**< \brief (SPI_CSR[4]) 13 bits for transfer */
#define   SPI_CSR_BITS_14_BIT (0x6u << 4) /**< \brief (SPI_CSR[4]) 14 bits for transfer */
#define   SPI_CSR_BITS_15_BIT (0x7u << 4) /**< \brief (SPI_CSR[4]) 15 bits for transfer */
#define   SPI_CSR_BITS_16_BIT (0x8u << 4) /**< \brief (SPI_CSR[4]) 16 bits for transfer */
#define SPI_CSR_SCBR_Pos 8
#define SPI_CSR_SCBR_Msk (0xffu << SPI_CSR_SCBR_Pos) /**< \brief (SPI_CSR[4]) Serial Clock Baud Rate */
#define SPI_CSR_SCBR(value) ((SPI_CSR_SCBR_Msk & ((value) << SPI_CSR_SCBR_Pos)))
#define SPI_CSR_DLYBS_Pos 16
#define SPI_CSR_DLYBS_Msk (0xffu << SPI_CSR_DLYBS_Pos) /**< \brief (SPI_CSR[4]) Delay Before SPCK */
#define SPI_CSR_DLYBS(value) ((SPI_CSR_DLYBS_Msk & ((value) << SPI_CSR_DLYBS_Pos)))
#define SPI_CSR_DLYBCT_Pos 24
#define SPI_CSR_DLYBCT_Msk (0xffu << SPI_CSR_DLYBCT_Pos) /**< \brief (SPI_CSR[4]) Delay Between Consecutive Transfers */
#define SPI_CSR_DLYBCT(value) ((SPI_CSR_DLYBCT_Msk & ((value) << SPI_CSR_DLYBCT_Pos)))
/* -------- SPI_WPMR : (SPI Offset: 0xE4) Write Protection Control Register -------- */
#define SPI_WPMR_SPIWPEN (0x1u << 0) /**< \brief (SPI_WPMR) SPI Write Protection Enable */
#define SPI_WPMR_SPIWPKEY_Pos 8
#define SPI_WPMR_SPIWPKEY_Msk (0xffffffu << SPI_WPMR_SPIWPKEY_Pos) /**< \brief (SPI_WPMR) SPI Write Protection Key Password */
#define SPI_WPMR_SPIWPKEY(value) ((SPI_WPMR_SPIWPKEY_Msk & ((value) << SPI_WPMR_SPIWPKEY_Pos)))
/* -------- SPI_WPSR : (SPI Offset: 0xE8) Write Protection Status Register -------- */
#define SPI_WPSR_SPIWPVS_Pos 0
#define SPI_WPSR_SPIWPVS_Msk (0x7u << SPI_WPSR_SPIWPVS_Pos) /**< \brief (SPI_WPSR) SPI Write Protection Violation Status */
#define SPI_WPSR_SPIWPVSRC_Pos 8
#define SPI_WPSR_SPIWPVSRC_Msk (0xffu << SPI_WPSR_SPIWPVSRC_Pos) /**< \brief (SPI_WPSR) SPI Write Protection Violation Source */

/*@}*/


/* ============================================================================= */
/**  SOFTWARE API DEFINITION FOR Timer Counter */
/* ============================================================================= */
/** \addtogroup SAM9N12_TC Timer Counter */
/*@{*/

#ifndef __ASSEMBLY__
/** \brief TcChannel hardware registers */
typedef struct {
  RwReg      TC_CCR;        /**< \brief (TcChannel Offset: 0x0) Channel Control Register */
  RwReg      TC_CMR;        /**< \brief (TcChannel Offset: 0x4) Channel Mode Register */
  RoReg      Reserved1[1];
  RwReg      TC_RAB;        /**< \brief (TcChannel Offset: 0xC) Register AB */
  RwReg      TC_CV;         /**< \brief (TcChannel Offset: 0x10) Counter Value */
  RwReg      TC_RA;         /**< \brief (TcChannel Offset: 0x14) Register A */
  RwReg      TC_RB;         /**< \brief (TcChannel Offset: 0x18) Register B */
  RwReg      TC_RC;         /**< \brief (TcChannel Offset: 0x1C) Register C */
  RwReg      TC_SR;         /**< \brief (TcChannel Offset: 0x20) Status Register */
  RwReg      TC_IER;        /**< \brief (TcChannel Offset: 0x24) Interrupt Enable Register */
  RwReg      TC_IDR;        /**< \brief (TcChannel Offset: 0x28) Interrupt Disable Register */
  RwReg      TC_IMR;        /**< \brief (TcChannel Offset: 0x2C) Interrupt Mask Register */
  RoReg      Reserved2[4];
} TcChannel;
/** \brief Tc hardware registers */
#define TCCHANNEL_NUMBER 3
typedef struct {
  TcChannel  TC_CHANNEL[TCCHANNEL_NUMBER]; /**< \brief (Tc Offset: 0x0) channel = 0 .. 2 */
  WoReg      TC_BCR;        /**< \brief (Tc Offset: 0xC0) Block Control Register */
  RwReg      TC_BMR;        /**< \brief (Tc Offset: 0xC4) Block Mode Register */
} Tc;
#endif /* __ASSEMBLY__ */
/* -------- TC_CCR : (TC Offset: N/A) Channel Control Register -------- */
#define TC_CCR_CLKEN (0x1u << 0) /**< \brief (TC_CCR) Counter Clock Enable Command */
#define TC_CCR_CLKDIS (0x1u << 1) /**< \brief (TC_CCR) Counter Clock Disable Command */
#define TC_CCR_SWTRG (0x1u << 2) /**< \brief (TC_CCR) Software Trigger Command */
/* -------- TC_CMR : (TC Offset: N/A) Channel Mode Register -------- */
#define TC_CMR_TCCLKS_Pos 0
#define TC_CMR_TCCLKS_Msk (0x7u << TC_CMR_TCCLKS_Pos) /**< \brief (TC_CMR) Clock Selection */
#define   TC_CMR_TCCLKS_TIMER_CLOCK1 (0x0u << 0) /**< \brief (TC_CMR) Clock selected: TCLK1 */
#define   TC_CMR_TCCLKS_TIMER_CLOCK2 (0x1u << 0) /**< \brief (TC_CMR) Clock selected: TCLK2 */
#define   TC_CMR_TCCLKS_TIMER_CLOCK3 (0x2u << 0) /**< \brief (TC_CMR) Clock selected: TCLK3 */
#define   TC_CMR_TCCLKS_TIMER_CLOCK4 (0x3u << 0) /**< \brief (TC_CMR) Clock selected: TCLK4 */
#define   TC_CMR_TCCLKS_TIMER_CLOCK5 (0x4u << 0) /**< \brief (TC_CMR) Clock selected: TCLK5 */
#define   TC_CMR_TCCLKS_XC0 (0x5u << 0) /**< \brief (TC_CMR) Clock selected: XC0 */
#define   TC_CMR_TCCLKS_XC1 (0x6u << 0) /**< \brief (TC_CMR) Clock selected: XC1 */
#define   TC_CMR_TCCLKS_XC2 (0x7u << 0) /**< \brief (TC_CMR) Clock selected: XC2 */
#define TC_CMR_CLKI (0x1u << 3) /**< \brief (TC_CMR) Clock Invert */
#define TC_CMR_BURST_Pos 4
#define TC_CMR_BURST_Msk (0x3u << TC_CMR_BURST_Pos) /**< \brief (TC_CMR) Burst Signal Selection */
#define   TC_CMR_BURST_NONE (0x0u << 4) /**< \brief (TC_CMR) The clock is not gated by an external signal. */
#define   TC_CMR_BURST_XC0 (0x1u << 4) /**< \brief (TC_CMR) XC0 is ANDed with the selected clock. */
#define   TC_CMR_BURST_XC1 (0x2u << 4) /**< \brief (TC_CMR) XC1 is ANDed with the selected clock. */
#define   TC_CMR_BURST_XC2 (0x3u << 4) /**< \brief (TC_CMR) XC2 is ANDed with the selected clock. */
#define TC_CMR_LDBSTOP (0x1u << 6) /**< \brief (TC_CMR) Counter Clock Stopped with RB Loading */
#define TC_CMR_LDBDIS (0x1u << 7) /**< \brief (TC_CMR) Counter Clock Disable with RB Loading */
#define TC_CMR_ETRGEDG_Pos 8
#define TC_CMR_ETRGEDG_Msk (0x3u << TC_CMR_ETRGEDG_Pos) /**< \brief (TC_CMR) External Trigger Edge Selection */
#define   TC_CMR_ETRGEDG_NONE (0x0u << 8) /**< \brief (TC_CMR) The clock is not gated by an external signal. */
#define   TC_CMR_ETRGEDG_RISING (0x1u << 8) /**< \brief (TC_CMR) Rising edge */
#define   TC_CMR_ETRGEDG_FALLING (0x2u << 8) /**< \brief (TC_CMR) Falling edge */
#define   TC_CMR_ETRGEDG_EDGE (0x3u << 8) /**< \brief (TC_CMR) Each edge */
#define TC_CMR_ABETRG (0x1u << 10) /**< \brief (TC_CMR) TIOA or TIOB External Trigger Selection */
#define TC_CMR_CPCTRG (0x1u << 14) /**< \brief (TC_CMR) RC Compare Trigger Enable */
#define TC_CMR_WAVE (0x1u << 15) /**< \brief (TC_CMR) Waveform Mode */
#define TC_CMR_LDRA_Pos 16
#define TC_CMR_LDRA_Msk (0x3u << TC_CMR_LDRA_Pos) /**< \brief (TC_CMR) RA Loading Edge Selection */
#define   TC_CMR_LDRA_NONE (0x0u << 16) /**< \brief (TC_CMR) None */
#define   TC_CMR_LDRA_RISING (0x1u << 16) /**< \brief (TC_CMR) Rising edge of TIOA */
#define   TC_CMR_LDRA_FALLING (0x2u << 16) /**< \brief (TC_CMR) Falling edge of TIOA */
#define   TC_CMR_LDRA_EDGE (0x3u << 16) /**< \brief (TC_CMR) Each edge of TIOA */
#define TC_CMR_LDRB_Pos 18
#define TC_CMR_LDRB_Msk (0x3u << TC_CMR_LDRB_Pos) /**< \brief (TC_CMR) RB Loading Edge Selection */
#define   TC_CMR_LDRB_NONE (0x0u << 18) /**< \brief (TC_CMR) None */
#define   TC_CMR_LDRB_RISING (0x1u << 18) /**< \brief (TC_CMR) Rising edge of TIOA */
#define   TC_CMR_LDRB_FALLING (0x2u << 18) /**< \brief (TC_CMR) Falling edge of TIOA */
#define   TC_CMR_LDRB_EDGE (0x3u << 18) /**< \brief (TC_CMR) Each edge of TIOA */
#define TC_CMR_CPCSTOP (0x1u << 6) /**< \brief (TC_CMR) Counter Clock Stopped with RC Compare */
#define TC_CMR_CPCDIS (0x1u << 7) /**< \brief (TC_CMR) Counter Clock Disable with RC Compare */
#define TC_CMR_EEVTEDG_Pos 8
#define TC_CMR_EEVTEDG_Msk (0x3u << TC_CMR_EEVTEDG_Pos) /**< \brief (TC_CMR) External Event Edge Selection */
#define   TC_CMR_EEVTEDG_NONE (0x0u << 8) /**< \brief (TC_CMR) None */
#define   TC_CMR_EEVTEDG_RISING (0x1u << 8) /**< \brief (TC_CMR) Rising edge */
#define   TC_CMR_EEVTEDG_FALLING (0x2u << 8) /**< \brief (TC_CMR) Falling edge */
#define   TC_CMR_EEVTEDG_EDGE (0x3u << 8) /**< \brief (TC_CMR) Each edge */
#define TC_CMR_EEVT_Pos 10
#define TC_CMR_EEVT_Msk (0x3u << TC_CMR_EEVT_Pos) /**< \brief (TC_CMR) External Event Selection */
#define   TC_CMR_EEVT_TIOB (0x0u << 10) /**< \brief (TC_CMR) TIOB */
#define   TC_CMR_EEVT_XC0 (0x1u << 10) /**< \brief (TC_CMR) XC0 */
#define   TC_CMR_EEVT_XC1 (0x2u << 10) /**< \brief (TC_CMR) XC1 */
#define   TC_CMR_EEVT_XC2 (0x3u << 10) /**< \brief (TC_CMR) XC2 */
#define TC_CMR_ENETRG (0x1u << 12) /**< \brief (TC_CMR) External Event Trigger Enable */
#define TC_CMR_WAVSEL_Pos 13
#define TC_CMR_WAVSEL_Msk (0x3u << TC_CMR_WAVSEL_Pos) /**< \brief (TC_CMR) Waveform Selection */
#define   TC_CMR_WAVSEL_UP (0x0u << 13) /**< \brief (TC_CMR) UP mode without automatic trigger on RC Compare */
#define   TC_CMR_WAVSEL_UPDOWN (0x1u << 13) /**< \brief (TC_CMR) UPDOWN mode without automatic trigger on RC Compare */
#define   TC_CMR_WAVSEL_UP_RC (0x2u << 13) /**< \brief (TC_CMR) UP mode with automatic trigger on RC Compare */
#define   TC_CMR_WAVSEL_UPDOWN_RC (0x3u << 13) /**< \brief (TC_CMR) UPDOWN mode with automatic trigger on RC Compare */
#define TC_CMR_ACPA_Pos 16
#define TC_CMR_ACPA_Msk (0x3u << TC_CMR_ACPA_Pos) /**< \brief (TC_CMR) RA Compare Effect on TIOA */
#define   TC_CMR_ACPA_NONE (0x0u << 16) /**< \brief (TC_CMR) None */
#define   TC_CMR_ACPA_SET (0x1u << 16) /**< \brief (TC_CMR) Set */
#define   TC_CMR_ACPA_CLEAR (0x2u << 16) /**< \brief (TC_CMR) Clear */
#define   TC_CMR_ACPA_TOGGLE (0x3u << 16) /**< \brief (TC_CMR) Toggle */
#define TC_CMR_ACPC_Pos 18
#define TC_CMR_ACPC_Msk (0x3u << TC_CMR_ACPC_Pos) /**< \brief (TC_CMR) RC Compare Effect on TIOA */
#define   TC_CMR_ACPC_NONE (0x0u << 18) /**< \brief (TC_CMR) None */
#define   TC_CMR_ACPC_SET (0x1u << 18) /**< \brief (TC_CMR) Set */
#define   TC_CMR_ACPC_CLEAR (0x2u << 18) /**< \brief (TC_CMR) Clear */
#define   TC_CMR_ACPC_TOGGLE (0x3u << 18) /**< \brief (TC_CMR) Toggle */
#define TC_CMR_AEEVT_Pos 20
#define TC_CMR_AEEVT_Msk (0x3u << TC_CMR_AEEVT_Pos) /**< \brief (TC_CMR) External Event Effect on TIOA */
#define   TC_CMR_AEEVT_NONE (0x0u << 20) /**< \brief (TC_CMR) None */
#define   TC_CMR_AEEVT_SET (0x1u << 20) /**< \brief (TC_CMR) Set */
#define   TC_CMR_AEEVT_CLEAR (0x2u << 20) /**< \brief (TC_CMR) Clear */
#define   TC_CMR_AEEVT_TOGGLE (0x3u << 20) /**< \brief (TC_CMR) Toggle */
#define TC_CMR_ASWTRG_Pos 22
#define TC_CMR_ASWTRG_Msk (0x3u << TC_CMR_ASWTRG_Pos) /**< \brief (TC_CMR) Software Trigger Effect on TIOA */
#define   TC_CMR_ASWTRG_NONE (0x0u << 22) /**< \brief (TC_CMR) None */
#define   TC_CMR_ASWTRG_SET (0x1u << 22) /**< \brief (TC_CMR) Set */
#define   TC_CMR_ASWTRG_CLEAR (0x2u << 22) /**< \brief (TC_CMR) Clear */
#define   TC_CMR_ASWTRG_TOGGLE (0x3u << 22) /**< \brief (TC_CMR) Toggle */
#define TC_CMR_BCPB_Pos 24
#define TC_CMR_BCPB_Msk (0x3u << TC_CMR_BCPB_Pos) /**< \brief (TC_CMR) RB Compare Effect on TIOB */
#define   TC_CMR_BCPB_NONE (0x0u << 24) /**< \brief (TC_CMR) None */
#define   TC_CMR_BCPB_SET (0x1u << 24) /**< \brief (TC_CMR) Set */
#define   TC_CMR_BCPB_CLEAR (0x2u << 24) /**< \brief (TC_CMR) Clear */
#define   TC_CMR_BCPB_TOGGLE (0x3u << 24) /**< \brief (TC_CMR) Toggle */
#define TC_CMR_BCPC_Pos 26
#define TC_CMR_BCPC_Msk (0x3u << TC_CMR_BCPC_Pos) /**< \brief (TC_CMR) RC Compare Effect on TIOB */
#define   TC_CMR_BCPC_NONE (0x0u << 26) /**< \brief (TC_CMR) None */
#define   TC_CMR_BCPC_SET (0x1u << 26) /**< \brief (TC_CMR) Set */
#define   TC_CMR_BCPC_CLEAR (0x2u << 26) /**< \brief (TC_CMR) Clear */
#define   TC_CMR_BCPC_TOGGLE (0x3u << 26) /**< \brief (TC_CMR) Toggle */
#define TC_CMR_BEEVT_Pos 28
#define TC_CMR_BEEVT_Msk (0x3u << TC_CMR_BEEVT_Pos) /**< \brief (TC_CMR) External Event Effect on TIOB */
#define   TC_CMR_BEEVT_NONE (0x0u << 28) /**< \brief (TC_CMR) None */
#define   TC_CMR_BEEVT_SET (0x1u << 28) /**< \brief (TC_CMR) Set */
#define   TC_CMR_BEEVT_CLEAR (0x2u << 28) /**< \brief (TC_CMR) Clear */
#define   TC_CMR_BEEVT_TOGGLE (0x3u << 28) /**< \brief (TC_CMR) Toggle */
#define TC_CMR_BSWTRG_Pos 30
#define TC_CMR_BSWTRG_Msk (0x3u << TC_CMR_BSWTRG_Pos) /**< \brief (TC_CMR) Software Trigger Effect on TIOB */
#define   TC_CMR_BSWTRG_NONE (0x0u << 30) /**< \brief (TC_CMR) None */
#define   TC_CMR_BSWTRG_SET (0x1u << 30) /**< \brief (TC_CMR) Set */
#define   TC_CMR_BSWTRG_CLEAR (0x2u << 30) /**< \brief (TC_CMR) Clear */
#define   TC_CMR_BSWTRG_TOGGLE (0x3u << 30) /**< \brief (TC_CMR) Toggle */
/* -------- TC_RAB : (TC Offset: N/A) Register AB -------- */
#define TC_RAB_RAB_Pos 0
#define TC_RAB_RAB_Msk (0xffffffffu << TC_RAB_RAB_Pos) /**< \brief (TC_RAB) Register A or Register B */
/* -------- TC_CV : (TC Offset: N/A) Counter Value -------- */
#define TC_CV_CV_Pos 0
#define TC_CV_CV_Msk (0xffffffffu << TC_CV_CV_Pos) /**< \brief (TC_CV) Counter Value */
/* -------- TC_RA : (TC Offset: N/A) Register A -------- */
#define TC_RA_RA_Pos 0
#define TC_RA_RA_Msk (0xffffffffu << TC_RA_RA_Pos) /**< \brief (TC_RA) Register A */
#define TC_RA_RA(value) ((TC_RA_RA_Msk & ((value) << TC_RA_RA_Pos)))
/* -------- TC_RB : (TC Offset: N/A) Register B -------- */
#define TC_RB_RB_Pos 0
#define TC_RB_RB_Msk (0xffffffffu << TC_RB_RB_Pos) /**< \brief (TC_RB) Register B */
#define TC_RB_RB(value) ((TC_RB_RB_Msk & ((value) << TC_RB_RB_Pos)))
/* -------- TC_RC : (TC Offset: N/A) Register C -------- */
#define TC_RC_RC_Pos 0
#define TC_RC_RC_Msk (0xffffffffu << TC_RC_RC_Pos) /**< \brief (TC_RC) Register C */
#define TC_RC_RC(value) ((TC_RC_RC_Msk & ((value) << TC_RC_RC_Pos)))
/* -------- TC_SR : (TC Offset: N/A) Status Register -------- */
#define TC_SR_COVFS (0x1u << 0) /**< \brief (TC_SR) Counter Overflow Status */
#define TC_SR_LOVRS (0x1u << 1) /**< \brief (TC_SR) Load Overrun Status */
#define TC_SR_CPAS (0x1u << 2) /**< \brief (TC_SR) RA Compare Status */
#define TC_SR_CPBS (0x1u << 3) /**< \brief (TC_SR) RB Compare Status */
#define TC_SR_CPCS (0x1u << 4) /**< \brief (TC_SR) RC Compare Status */
#define TC_SR_LDRAS (0x1u << 5) /**< \brief (TC_SR) RA Loading Status */
#define TC_SR_LDRBS (0x1u << 6) /**< \brief (TC_SR) RB Loading Status */
#define TC_SR_ETRGS (0x1u << 7) /**< \brief (TC_SR) External Trigger Status */
#define TC_SR_CLKSTA (0x1u << 16) /**< \brief (TC_SR) Clock Enabling Status */
#define TC_SR_MTIOA (0x1u << 17) /**< \brief (TC_SR) TIOA Mirror */
#define TC_SR_MTIOB (0x1u << 18) /**< \brief (TC_SR) TIOB Mirror */
/* -------- TC_IER : (TC Offset: N/A) Interrupt Enable Register -------- */
#define TC_IER_COVFS (0x1u << 0) /**< \brief (TC_IER) Counter Overflow */
#define TC_IER_LOVRS (0x1u << 1) /**< \brief (TC_IER) Load Overrun */
#define TC_IER_CPAS (0x1u << 2) /**< \brief (TC_IER) RA Compare */
#define TC_IER_CPBS (0x1u << 3) /**< \brief (TC_IER) RB Compare */
#define TC_IER_CPCS (0x1u << 4) /**< \brief (TC_IER) RC Compare */
#define TC_IER_LDRAS (0x1u << 5) /**< \brief (TC_IER) RA Loading */
#define TC_IER_LDRBS (0x1u << 6) /**< \brief (TC_IER) RB Loading */
#define TC_IER_ETRGS (0x1u << 7) /**< \brief (TC_IER) External Trigger */
/* -------- TC_IDR : (TC Offset: N/A) Interrupt Disable Register -------- */
#define TC_IDR_COVFS (0x1u << 0) /**< \brief (TC_IDR) Counter Overflow */
#define TC_IDR_LOVRS (0x1u << 1) /**< \brief (TC_IDR) Load Overrun */
#define TC_IDR_CPAS (0x1u << 2) /**< \brief (TC_IDR) RA Compare */
#define TC_IDR_CPBS (0x1u << 3) /**< \brief (TC_IDR) RB Compare */
#define TC_IDR_CPCS (0x1u << 4) /**< \brief (TC_IDR) RC Compare */
#define TC_IDR_LDRAS (0x1u << 5) /**< \brief (TC_IDR) RA Loading */
#define TC_IDR_LDRBS (0x1u << 6) /**< \brief (TC_IDR) RB Loading */
#define TC_IDR_ETRGS (0x1u << 7) /**< \brief (TC_IDR) External Trigger */
/* -------- TC_IMR : (TC Offset: N/A) Interrupt Mask Register -------- */
#define TC_IMR_COVFS (0x1u << 0) /**< \brief (TC_IMR) Counter Overflow */
#define TC_IMR_LOVRS (0x1u << 1) /**< \brief (TC_IMR) Load Overrun */
#define TC_IMR_CPAS (0x1u << 2) /**< \brief (TC_IMR) RA Compare */
#define TC_IMR_CPBS (0x1u << 3) /**< \brief (TC_IMR) RB Compare */
#define TC_IMR_CPCS (0x1u << 4) /**< \brief (TC_IMR) RC Compare */
#define TC_IMR_LDRAS (0x1u << 5) /**< \brief (TC_IMR) RA Loading */
#define TC_IMR_LDRBS (0x1u << 6) /**< \brief (TC_IMR) RB Loading */
#define TC_IMR_ETRGS (0x1u << 7) /**< \brief (TC_IMR) External Trigger */
/* -------- TC_BCR : (TC Offset: 0xC0) Block Control Register -------- */
#define TC_BCR_SYNC (0x1u << 0) /**< \brief (TC_BCR) Synchro Command */
/* -------- TC_BMR : (TC Offset: 0xC4) Block Mode Register -------- */
#define TC_BMR_TC0XC0S_Pos 0
#define TC_BMR_TC0XC0S_Msk (0x3u << TC_BMR_TC0XC0S_Pos) /**< \brief (TC_BMR) External Clock Signal 0 Selection */
#define   TC_BMR_TC0XC0S_TCLK0 (0x0u << 0) /**< \brief (TC_BMR) Signal connected to XC0: TCLK0 */
#define   TC_BMR_TC0XC0S_TIOA1 (0x2u << 0) /**< \brief (TC_BMR) Signal connected to XC0: TIOA1 */
#define   TC_BMR_TC0XC0S_TIOA2 (0x3u << 0) /**< \brief (TC_BMR) Signal connected to XC0: TIOA2 */
#define TC_BMR_TC1XC1S_Pos 2
#define TC_BMR_TC1XC1S_Msk (0x3u << TC_BMR_TC1XC1S_Pos) /**< \brief (TC_BMR) External Clock Signal 1 Selection */
#define   TC_BMR_TC1XC1S_TCLK1 (0x0u << 2) /**< \brief (TC_BMR) Signal connected to XC1: TCLK1 */
#define   TC_BMR_TC1XC1S_TIOA0 (0x2u << 2) /**< \brief (TC_BMR) Signal connected to XC1: TIOA0 */
#define   TC_BMR_TC1XC1S_TIOA2 (0x3u << 2) /**< \brief (TC_BMR) Signal connected to XC1: TIOA2 */
#define TC_BMR_TC2XC2S_Pos 4
#define TC_BMR_TC2XC2S_Msk (0x3u << TC_BMR_TC2XC2S_Pos) /**< \brief (TC_BMR) External Clock Signal 2 Selection */
#define   TC_BMR_TC2XC2S_TCLK2 (0x0u << 4) /**< \brief (TC_BMR) Signal connected to XC2: TCLK2 */
#define   TC_BMR_TC2XC2S_TIOA1 (0x2u << 4) /**< \brief (TC_BMR) Signal connected to XC2: TIOA1 */
#define   TC_BMR_TC2XC2S_TIOA2 (0x3u << 4) /**< \brief (TC_BMR) Signal connected to XC2: TIOA2 */

/*@}*/

/* ============================================================================= */
/**  SOFTWARE API DEFINITION FOR Two-wire Interface */
/* ============================================================================= */
/** \addtogroup SAM9N12_TWI Two-wire Interface */
/*@{*/

#ifndef __ASSEMBLY__
/** \brief Twi hardware registers */
typedef struct {
  WoReg TWI_CR;       /**< \brief (Twi Offset: 0x00) Control Register */
  RwReg TWI_MMR;      /**< \brief (Twi Offset: 0x04) Master Mode Register */
  RwReg TWI_SMR;      /**< \brief (Twi Offset: 0x08) Slave Mode Register */
  RwReg TWI_IADR;     /**< \brief (Twi Offset: 0x0C) Internal Address Register */
  RwReg TWI_CWGR;     /**< \brief (Twi Offset: 0x10) Clock Waveform Generator Register */
  RoReg Reserved1[3];
  RoReg TWI_SR;       /**< \brief (Twi Offset: 0x20) Status Register */
  WoReg TWI_IER;      /**< \brief (Twi Offset: 0x24) Interrupt Enable Register */
  WoReg TWI_IDR;      /**< \brief (Twi Offset: 0x28) Interrupt Disable Register */
  RoReg TWI_IMR;      /**< \brief (Twi Offset: 0x2C) Interrupt Mask Register */
  RoReg TWI_RHR;      /**< \brief (Twi Offset: 0x30) Receive Holding Register */
  WoReg TWI_THR;      /**< \brief (Twi Offset: 0x34) Transmit Holding Register */
} Twi;
#endif /* __ASSEMBLY__ */
/* -------- TWI_CR : (TWI Offset: 0x00) Control Register -------- */
#define TWI_CR_START (0x1u << 0) /**< \brief (TWI_CR) Send a START Condition */
#define TWI_CR_STOP (0x1u << 1) /**< \brief (TWI_CR) Send a STOP Condition */
#define TWI_CR_MSEN (0x1u << 2) /**< \brief (TWI_CR) TWI Master Mode Enabled */
#define TWI_CR_MSDIS (0x1u << 3) /**< \brief (TWI_CR) TWI Master Mode Disabled */
#define TWI_CR_SVEN (0x1u << 4) /**< \brief (TWI_CR) TWI Slave Mode Enabled */
#define TWI_CR_SVDIS (0x1u << 5) /**< \brief (TWI_CR) TWI Slave Mode Disabled */
#define TWI_CR_QUICK (0x1u << 6) /**< \brief (TWI_CR) SMBUS Quick Command */
#define TWI_CR_SWRST (0x1u << 7) /**< \brief (TWI_CR) Software Reset */
/* -------- TWI_MMR : (TWI Offset: 0x04) Master Mode Register -------- */
#define TWI_MMR_IADRSZ_Pos 8
#define TWI_MMR_IADRSZ_Msk (0x3u << TWI_MMR_IADRSZ_Pos) /**< \brief (TWI_MMR) Internal Device Address Size */
#define   TWI_MMR_IADRSZ_NONE (0x0u << 8) /**< \brief (TWI_MMR) No internal device address */
#define   TWI_MMR_IADRSZ_1_BYTE (0x1u << 8) /**< \brief (TWI_MMR) One-byte internal device address */
#define   TWI_MMR_IADRSZ_2_BYTE (0x2u << 8) /**< \brief (TWI_MMR) Two-byte internal device address */
#define   TWI_MMR_IADRSZ_3_BYTE (0x3u << 8) /**< \brief (TWI_MMR) Three-byte internal device address */
#define TWI_MMR_MREAD (0x1u << 12) /**< \brief (TWI_MMR) Master Read Direction */
#define TWI_MMR_DADR_Pos 16
#define TWI_MMR_DADR_Msk (0x7fu << TWI_MMR_DADR_Pos) /**< \brief (TWI_MMR) Device Address */
#define TWI_MMR_DADR(value) ((TWI_MMR_DADR_Msk & ((value) << TWI_MMR_DADR_Pos)))
/* -------- TWI_SMR : (TWI Offset: 0x08) Slave Mode Register -------- */
#define TWI_SMR_SADR_Pos 16
#define TWI_SMR_SADR_Msk (0x7fu << TWI_SMR_SADR_Pos) /**< \brief (TWI_SMR) Slave Address */
#define TWI_SMR_SADR(value) ((TWI_SMR_SADR_Msk & ((value) << TWI_SMR_SADR_Pos)))
/* -------- TWI_IADR : (TWI Offset: 0x0C) Internal Address Register -------- */
#define TWI_IADR_IADR_Pos 0
#define TWI_IADR_IADR_Msk (0xffffffu << TWI_IADR_IADR_Pos) /**< \brief (TWI_IADR) Internal Address */
#define TWI_IADR_IADR(value) ((TWI_IADR_IADR_Msk & ((value) << TWI_IADR_IADR_Pos)))
/* -------- TWI_CWGR : (TWI Offset: 0x10) Clock Waveform Generator Register -------- */
#define TWI_CWGR_CLDIV_Pos 0
#define TWI_CWGR_CLDIV_Msk (0xffu << TWI_CWGR_CLDIV_Pos) /**< \brief (TWI_CWGR) Clock Low Divider */
#define TWI_CWGR_CLDIV(value) ((TWI_CWGR_CLDIV_Msk & ((value) << TWI_CWGR_CLDIV_Pos)))
#define TWI_CWGR_CHDIV_Pos 8
#define TWI_CWGR_CHDIV_Msk (0xffu << TWI_CWGR_CHDIV_Pos) /**< \brief (TWI_CWGR) Clock High Divider */
#define TWI_CWGR_CHDIV(value) ((TWI_CWGR_CHDIV_Msk & ((value) << TWI_CWGR_CHDIV_Pos)))
#define TWI_CWGR_CKDIV_Pos 16
#define TWI_CWGR_CKDIV_Msk (0x7u << TWI_CWGR_CKDIV_Pos) /**< \brief (TWI_CWGR) Clock Divider */
#define TWI_CWGR_CKDIV(value) ((TWI_CWGR_CKDIV_Msk & ((value) << TWI_CWGR_CKDIV_Pos)))
/* -------- TWI_SR : (TWI Offset: 0x20) Status Register -------- */
#define TWI_SR_TXCOMP (0x1u << 0) /**< \brief (TWI_SR) Transmission Completed (automatically set / reset) */
#define TWI_SR_RXRDY (0x1u << 1) /**< \brief (TWI_SR) Receive Holding Register Ready (automatically set / reset) */
#define TWI_SR_TXRDY (0x1u << 2) /**< \brief (TWI_SR) Transmit Holding Register Ready (automatically set / reset) */
#define TWI_SR_SVREAD (0x1u << 3) /**< \brief (TWI_SR) Slave Read (automatically set / reset) */
#define TWI_SR_SVACC (0x1u << 4) /**< \brief (TWI_SR) Slave Access (automatically set / reset) */
#define TWI_SR_GACC (0x1u << 5) /**< \brief (TWI_SR) General Call Access (clear on read) */
#define TWI_SR_OVRE (0x1u << 6) /**< \brief (TWI_SR) Overrun Error (clear on read) */
#define TWI_SR_NACK (0x1u << 8) /**< \brief (TWI_SR) Not Acknowledged (clear on read) */
#define TWI_SR_ARBLST (0x1u << 9) /**< \brief (TWI_SR) Arbitration Lost (clear on read) */
#define TWI_SR_SCLWS (0x1u << 10) /**< \brief (TWI_SR) Clock Wait State (automatically set / reset) */
#define TWI_SR_EOSACC (0x1u << 11) /**< \brief (TWI_SR) End Of Slave Access (clear on read) */
/* -------- TWI_IER : (TWI Offset: 0x24) Interrupt Enable Register -------- */
#define TWI_IER_TXCOMP (0x1u << 0) /**< \brief (TWI_IER) Transmission Completed Interrupt Enable */
#define TWI_IER_RXRDY (0x1u << 1) /**< \brief (TWI_IER) Receive Holding Register Ready Interrupt Enable */
#define TWI_IER_TXRDY (0x1u << 2) /**< \brief (TWI_IER) Transmit Holding Register Ready Interrupt Enable */
#define TWI_IER_SVACC (0x1u << 4) /**< \brief (TWI_IER) Slave Access Interrupt Enable */
#define TWI_IER_GACC (0x1u << 5) /**< \brief (TWI_IER) General Call Access Interrupt Enable */
#define TWI_IER_OVRE (0x1u << 6) /**< \brief (TWI_IER) Overrun Error Interrupt Enable */
#define TWI_IER_NACK (0x1u << 8) /**< \brief (TWI_IER) Not Acknowledge Interrupt Enable */
#define TWI_IER_ARBLST (0x1u << 9) /**< \brief (TWI_IER) Arbitration Lost Interrupt Enable */
#define TWI_IER_SCL_WS (0x1u << 10) /**< \brief (TWI_IER) Clock Wait State Interrupt Enable */
#define TWI_IER_EOSACC (0x1u << 11) /**< \brief (TWI_IER) End Of Slave Access Interrupt Enable */
/* -------- TWI_IDR : (TWI Offset: 0x28) Interrupt Disable Register -------- */
#define TWI_IDR_TXCOMP (0x1u << 0) /**< \brief (TWI_IDR) Transmission Completed Interrupt Disable */
#define TWI_IDR_RXRDY (0x1u << 1) /**< \brief (TWI_IDR) Receive Holding Register Ready Interrupt Disable */
#define TWI_IDR_TXRDY (0x1u << 2) /**< \brief (TWI_IDR) Transmit Holding Register Ready Interrupt Disable */
#define TWI_IDR_SVACC (0x1u << 4) /**< \brief (TWI_IDR) Slave Access Interrupt Disable */
#define TWI_IDR_GACC (0x1u << 5) /**< \brief (TWI_IDR) General Call Access Interrupt Disable */
#define TWI_IDR_OVRE (0x1u << 6) /**< \brief (TWI_IDR) Overrun Error Interrupt Disable */
#define TWI_IDR_NACK (0x1u << 8) /**< \brief (TWI_IDR) Not Acknowledge Interrupt Disable */
#define TWI_IDR_ARBLST (0x1u << 9) /**< \brief (TWI_IDR) Arbitration Lost Interrupt Disable */
#define TWI_IDR_SCL_WS (0x1u << 10) /**< \brief (TWI_IDR) Clock Wait State Interrupt Disable */
#define TWI_IDR_EOSACC (0x1u << 11) /**< \brief (TWI_IDR) End Of Slave Access Interrupt Disable */
/* -------- TWI_IMR : (TWI Offset: 0x2C) Interrupt Mask Register -------- */
#define TWI_IMR_TXCOMP (0x1u << 0) /**< \brief (TWI_IMR) Transmission Completed Interrupt Mask */
#define TWI_IMR_RXRDY (0x1u << 1) /**< \brief (TWI_IMR) Receive Holding Register Ready Interrupt Mask */
#define TWI_IMR_TXRDY (0x1u << 2) /**< \brief (TWI_IMR) Transmit Holding Register Ready Interrupt Mask */
#define TWI_IMR_SVACC (0x1u << 4) /**< \brief (TWI_IMR) Slave Access Interrupt Mask */
#define TWI_IMR_GACC (0x1u << 5) /**< \brief (TWI_IMR) General Call Access Interrupt Mask */
#define TWI_IMR_OVRE (0x1u << 6) /**< \brief (TWI_IMR) Overrun Error Interrupt Mask */
#define TWI_IMR_NACK (0x1u << 8) /**< \brief (TWI_IMR) Not Acknowledge Interrupt Mask */
#define TWI_IMR_ARBLST (0x1u << 9) /**< \brief (TWI_IMR) Arbitration Lost Interrupt Mask */
#define TWI_IMR_SCL_WS (0x1u << 10) /**< \brief (TWI_IMR) Clock Wait State Interrupt Mask */
#define TWI_IMR_EOSACC (0x1u << 11) /**< \brief (TWI_IMR) End Of Slave Access Interrupt Mask */
/* -------- TWI_RHR : (TWI Offset: 0x30) Receive Holding Register -------- */
#define TWI_RHR_RXDATA_Pos 0
#define TWI_RHR_RXDATA_Msk (0xffu << TWI_RHR_RXDATA_Pos) /**< \brief (TWI_RHR) Master or Slave Receive Holding Data */
/* -------- TWI_THR : (TWI Offset: 0x34) Transmit Holding Register -------- */
#define TWI_THR_TXDATA_Pos 0
#define TWI_THR_TXDATA_Msk (0xffu << TWI_THR_TXDATA_Pos) /**< \brief (TWI_THR) Master or Slave Transmit Holding Data */
#define TWI_THR_TXDATA(value) ((TWI_THR_TXDATA_Msk & ((value) << TWI_THR_TXDATA_Pos)))

/*@}*/

/* ============================================================================= */
/**  SOFTWARE API DEFINITION FOR Universal Asynchronous Receiver Transmitter */
/* ============================================================================= */
/** \addtogroup SAM9N12_UART Universal Asynchronous Receiver Transmitter */
/*@{*/

#ifndef __ASSEMBLY__
/** \brief Uart hardware registers */
typedef struct {
  WoReg UART_CR;   /**< \brief (Uart Offset: 0x0000) Control Register */
  RwReg UART_MR;   /**< \brief (Uart Offset: 0x0004) Mode Register */
  WoReg UART_IER;  /**< \brief (Uart Offset: 0x0008) Interrupt Enable Register */
  WoReg UART_IDR;  /**< \brief (Uart Offset: 0x000C) Interrupt Disable Register */
  RoReg UART_IMR;  /**< \brief (Uart Offset: 0x0010) Interrupt Mask Register */
  RoReg UART_SR;   /**< \brief (Uart Offset: 0x0014) Status Register */
  RoReg UART_RHR;  /**< \brief (Uart Offset: 0x0018) Receive Holding Register */
  WoReg UART_THR;  /**< \brief (Uart Offset: 0x001C) Transmit Holding Register */
  RwReg UART_BRGR; /**< \brief (Uart Offset: 0x0020) Baud Rate Generator Register */
} Uart;
#endif /* __ASSEMBLY__ */
/* -------- UART_CR : (UART Offset: 0x0000) Control Register -------- */
#define UART_CR_RSTRX (0x1u << 2) /**< \brief (UART_CR) Reset Receiver */
#define UART_CR_RSTTX (0x1u << 3) /**< \brief (UART_CR) Reset Transmitter */
#define UART_CR_RXEN (0x1u << 4) /**< \brief (UART_CR) Receiver Enable */
#define UART_CR_RXDIS (0x1u << 5) /**< \brief (UART_CR) Receiver Disable */
#define UART_CR_TXEN (0x1u << 6) /**< \brief (UART_CR) Transmitter Enable */
#define UART_CR_TXDIS (0x1u << 7) /**< \brief (UART_CR) Transmitter Disable */
#define UART_CR_RSTSTA (0x1u << 8) /**< \brief (UART_CR) Reset Status Bits */
/* -------- UART_MR : (UART Offset: 0x0004) Mode Register -------- */
#define UART_MR_PAR_Pos 9
#define UART_MR_PAR_Msk (0x7u << UART_MR_PAR_Pos) /**< \brief (UART_MR) Parity Type */
#define   UART_MR_PAR_EVEN (0x0u << 9) /**< \brief (UART_MR) Even parity */
#define   UART_MR_PAR_ODD (0x1u << 9) /**< \brief (UART_MR) Odd parity */
#define   UART_MR_PAR_SPACE (0x2u << 9) /**< \brief (UART_MR) Space: parity forced to 0 */
#define   UART_MR_PAR_MARK (0x3u << 9) /**< \brief (UART_MR) Mark: parity forced to 1 */
#define   UART_MR_PAR_NO (0x4u << 9) /**< \brief (UART_MR) No parity */
#define UART_MR_CHMODE_Pos 14
#define UART_MR_CHMODE_Msk (0x3u << UART_MR_CHMODE_Pos) /**< \brief (UART_MR) Channel Mode */
#define   UART_MR_CHMODE_NORMAL (0x0u << 14) /**< \brief (UART_MR) Normal Mode */
#define   UART_MR_CHMODE_AUTOMATIC (0x1u << 14) /**< \brief (UART_MR) Automatic Echo */
#define   UART_MR_CHMODE_LOCAL_LOOPBACK (0x2u << 14) /**< \brief (UART_MR) Local Loopback */
#define   UART_MR_CHMODE_REMOTE_LOOPBACK (0x3u << 14) /**< \brief (UART_MR) Remote Loopback */
/* -------- UART_IER : (UART Offset: 0x0008) Interrupt Enable Register -------- */
#define UART_IER_RXRDY (0x1u << 0) /**< \brief (UART_IER) Enable RXRDY Interrupt */
#define UART_IER_TXRDY (0x1u << 1) /**< \brief (UART_IER) Enable TXRDY Interrupt */
#define UART_IER_OVRE (0x1u << 5) /**< \brief (UART_IER) Enable Overrun Error Interrupt */
#define UART_IER_FRAME (0x1u << 6) /**< \brief (UART_IER) Enable Framing Error Interrupt */
#define UART_IER_PARE (0x1u << 7) /**< \brief (UART_IER) Enable Parity Error Interrupt */
#define UART_IER_TXEMPTY (0x1u << 9) /**< \brief (UART_IER) Enable TXEMPTY Interrupt */
/* -------- UART_IDR : (UART Offset: 0x000C) Interrupt Disable Register -------- */
#define UART_IDR_RXRDY (0x1u << 0) /**< \brief (UART_IDR) Disable RXRDY Interrupt */
#define UART_IDR_TXRDY (0x1u << 1) /**< \brief (UART_IDR) Disable TXRDY Interrupt */
#define UART_IDR_OVRE (0x1u << 5) /**< \brief (UART_IDR) Disable Overrun Error Interrupt */
#define UART_IDR_FRAME (0x1u << 6) /**< \brief (UART_IDR) Disable Framing Error Interrupt */
#define UART_IDR_PARE (0x1u << 7) /**< \brief (UART_IDR) Disable Parity Error Interrupt */
#define UART_IDR_TXEMPTY (0x1u << 9) /**< \brief (UART_IDR) Disable TXEMPTY Interrupt */
/* -------- UART_IMR : (UART Offset: 0x0010) Interrupt Mask Register -------- */
#define UART_IMR_RXRDY (0x1u << 0) /**< \brief (UART_IMR) Mask RXRDY Interrupt */
#define UART_IMR_TXRDY (0x1u << 1) /**< \brief (UART_IMR) Disable TXRDY Interrupt */
#define UART_IMR_OVRE (0x1u << 5) /**< \brief (UART_IMR) Mask Overrun Error Interrupt */
#define UART_IMR_FRAME (0x1u << 6) /**< \brief (UART_IMR) Mask Framing Error Interrupt */
#define UART_IMR_PARE (0x1u << 7) /**< \brief (UART_IMR) Mask Parity Error Interrupt */
#define UART_IMR_TXEMPTY (0x1u << 9) /**< \brief (UART_IMR) Mask TXEMPTY Interrupt */
/* -------- UART_SR : (UART Offset: 0x0014) Status Register -------- */
#define UART_SR_RXRDY (0x1u << 0) /**< \brief (UART_SR) Receiver Ready */
#define UART_SR_TXRDY (0x1u << 1) /**< \brief (UART_SR) Transmitter Ready */
#define UART_SR_OVRE (0x1u << 5) /**< \brief (UART_SR) Overrun Error */
#define UART_SR_FRAME (0x1u << 6) /**< \brief (UART_SR) Framing Error */
#define UART_SR_PARE (0x1u << 7) /**< \brief (UART_SR) Parity Error */
#define UART_SR_TXEMPTY (0x1u << 9) /**< \brief (UART_SR) Transmitter Empty */
/* -------- UART_RHR : (UART Offset: 0x0018) Receive Holding Register -------- */
#define UART_RHR_RXCHR_Pos 0
#define UART_RHR_RXCHR_Msk (0xffu << UART_RHR_RXCHR_Pos) /**< \brief (UART_RHR) Received Character */
/* -------- UART_THR : (UART Offset: 0x001C) Transmit Holding Register -------- */
#define UART_THR_TXCHR_Pos 0
#define UART_THR_TXCHR_Msk (0xffu << UART_THR_TXCHR_Pos) /**< \brief (UART_THR) Character to be Transmitted */
#define UART_THR_TXCHR(value) ((UART_THR_TXCHR_Msk & ((value) << UART_THR_TXCHR_Pos)))
/* -------- UART_BRGR : (UART Offset: 0x0020) Baud Rate Generator Register -------- */
#define UART_BRGR_CD_Pos 0
#define UART_BRGR_CD_Msk (0xffffu << UART_BRGR_CD_Pos) /**< \brief (UART_BRGR) Clock Divisor */
#define UART_BRGR_CD(value) ((UART_BRGR_CD_Msk & ((value) << UART_BRGR_CD_Pos)))

/* ============================================================================= */
/**  SOFTWARE API DEFINITION FOR Universal Synchronous Asynchronous Receiver Transmitter */
/* ============================================================================= */
/** \addtogroup SAM9N12_USART Universal Synchronous Asynchronous Receiver Transmitter */
/*@{*/

#ifndef __ASSEMBLY__
/** \brief Usart hardware registers */
typedef struct {
  WoReg US_CR;         /**< \brief (Usart Offset: 0x0000) Control Register */
  RwReg US_MR;         /**< \brief (Usart Offset: 0x0004) Mode Register */
  WoReg US_IER;        /**< \brief (Usart Offset: 0x0008) Interrupt Enable Register */
  WoReg US_IDR;        /**< \brief (Usart Offset: 0x000C) Interrupt Disable Register */
  RoReg US_IMR;        /**< \brief (Usart Offset: 0x0010) Interrupt Mask Register */
  RoReg US_CSR;        /**< \brief (Usart Offset: 0x0014) Channel Status Register */
  RoReg US_RHR;        /**< \brief (Usart Offset: 0x0018) Receiver Holding Register */
  WoReg US_THR;        /**< \brief (Usart Offset: 0x001C) Transmitter Holding Register */
  RwReg US_BRGR;       /**< \brief (Usart Offset: 0x0020) Baud Rate Generator Register */
  RwReg US_RTOR;       /**< \brief (Usart Offset: 0x0024) Receiver Time-out Register */
  RwReg US_TTGR;       /**< \brief (Usart Offset: 0x0028) Transmitter Timeguard Register */
  RoReg Reserved1[5];
  RwReg US_FIDI;       /**< \brief (Usart Offset: 0x0040) FI DI Ratio Register */
  RoReg US_NER;        /**< \brief (Usart Offset: 0x0044) Number of Errors Register */
  RoReg Reserved2[1];
  RwReg US_IF;         /**< \brief (Usart Offset: 0x004C) IrDA Filter Register */
  RwReg US_MAN;        /**< \brief (Usart Offset: 0x0050) Manchester Encoder Decoder Register */
  RwReg US_LINMR;      /**< \brief (Usart Offset: 0x0054) LIN Mode Register */
  RwReg US_LINIR;      /**< \brief (Usart Offset: 0x0058) LIN Identifier Register */
  RoReg Reserved3[34];
  RwReg US_WPMR;       /**< \brief (Usart Offset: 0xE4) Write Protect Mode Register */
  RoReg US_WPSR;       /**< \brief (Usart Offset: 0xE8) Write Protect Status Register */
} Usart;
#endif /* __ASSEMBLY__ */
/* -------- US_CR : (USART Offset: 0x0000) Control Register -------- */
#define US_CR_RSTRX (0x1u << 2) /**< \brief (US_CR) Reset Receiver */
#define US_CR_RSTTX (0x1u << 3) /**< \brief (US_CR) Reset Transmitter */
#define US_CR_RXEN (0x1u << 4) /**< \brief (US_CR) Receiver Enable */
#define US_CR_RXDIS (0x1u << 5) /**< \brief (US_CR) Receiver Disable */
#define US_CR_TXEN (0x1u << 6) /**< \brief (US_CR) Transmitter Enable */
#define US_CR_TXDIS (0x1u << 7) /**< \brief (US_CR) Transmitter Disable */
#define US_CR_RSTSTA (0x1u << 8) /**< \brief (US_CR) Reset Status Bits */
#define US_CR_STTBRK (0x1u << 9) /**< \brief (US_CR) Start Break */
#define US_CR_STPBRK (0x1u << 10) /**< \brief (US_CR) Stop Break */
#define US_CR_STTTO (0x1u << 11) /**< \brief (US_CR) Start Time-out */
#define US_CR_SENDA (0x1u << 12) /**< \brief (US_CR) Send Address */
#define US_CR_RSTIT (0x1u << 13) /**< \brief (US_CR) Reset Iterations */
#define US_CR_RSTNACK (0x1u << 14) /**< \brief (US_CR) Reset Non Acknowledge */
#define US_CR_RETTO (0x1u << 15) /**< \brief (US_CR) Rearm Time-out */
#define US_CR_RTSEN (0x1u << 18) /**< \brief (US_CR) Request to Send Enable */
#define US_CR_FCS (0x1u << 18) /**< \brief (US_CR) Force SPI Chip Select */
#define US_CR_RTSDIS (0x1u << 19) /**< \brief (US_CR) Request to Send Disable */
#define US_CR_RCS (0x1u << 19) /**< \brief (US_CR) Release SPI Chip Select */
#define US_CR_LINABT (0x1u << 20) /**< \brief (US_CR) Abort LIN Transmission */
#define US_CR_LINWKUP (0x1u << 21) /**< \brief (US_CR) Send LIN Wakeup Signal */
/* -------- US_MR : (USART Offset: 0x0004) Mode Register -------- */
#define US_MR_USART_MODE_Pos 0
#define US_MR_USART_MODE_Msk (0xfu << US_MR_USART_MODE_Pos) /**< \brief (US_MR)  */
#define   US_MR_USART_MODE_NORMAL (0x0u << 0) /**< \brief (US_MR) Normal mode */
#define   US_MR_USART_MODE_RS485 (0x1u << 0) /**< \brief (US_MR) RS485 */
#define   US_MR_USART_MODE_HW_HANDSHAKING (0x2u << 0) /**< \brief (US_MR) Hardware Handshaking */
#define   US_MR_USART_MODE_IS07816_T_0 (0x4u << 0) /**< \brief (US_MR) IS07816 Protocol: T = 0 */
#define   US_MR_USART_MODE_IS07816_T_1 (0x6u << 0) /**< \brief (US_MR) IS07816 Protocol: T = 1 */
#define   US_MR_USART_MODE_IRDA (0x8u << 0) /**< \brief (US_MR) IrDA */
#define   US_MR_USART_MODE_LIN_MASTER (0xAu << 0) /**< \brief (US_MR) LIN Master */
#define   US_MR_USART_MODE_LIN_SLAVE (0xBu << 0) /**< \brief (US_MR) LIN Slave */
#define   US_MR_USART_MODE_SPI_MASTER (0xEu << 0) /**< \brief (US_MR) SPI Master */
#define   US_MR_USART_MODE_SPI_SLAVE (0xFu << 0) /**< \brief (US_MR) SPI Slave */
#define US_MR_USCLKS_Pos 4
#define US_MR_USCLKS_Msk (0x3u << US_MR_USCLKS_Pos) /**< \brief (US_MR) Clock Selection */
#define   US_MR_USCLKS_MCK (0x0u << 4) /**< \brief (US_MR) Master Clock MCK is selected */
#define   US_MR_USCLKS_DIV (0x1u << 4) /**< \brief (US_MR) Internal Clock Divided MCK/DIV (DIV=8) is selected */
#define   US_MR_USCLKS_SCK (0x3u << 4) /**< \brief (US_MR) Serial Clock SLK is selected */
#define US_MR_CHRL_Pos 6
#define US_MR_CHRL_Msk (0x3u << US_MR_CHRL_Pos) /**< \brief (US_MR) Character Length. */
#define   US_MR_CHRL_5_BIT (0x0u << 6) /**< \brief (US_MR) Character length is 5 bits */
#define   US_MR_CHRL_6_BIT (0x1u << 6) /**< \brief (US_MR) Character length is 6 bits */
#define   US_MR_CHRL_7_BIT (0x2u << 6) /**< \brief (US_MR) Character length is 7 bits */
#define   US_MR_CHRL_8_BIT (0x3u << 6) /**< \brief (US_MR) Character length is 8 bits */
#define US_MR_SYNC (0x1u << 8) /**< \brief (US_MR) Synchronous Mode Select */
#define US_MR_CPHA (0x1u << 8) /**< \brief (US_MR) SPI Clock Phase */
#define US_MR_PAR_Pos 9
#define US_MR_PAR_Msk (0x7u << US_MR_PAR_Pos) /**< \brief (US_MR) Parity Type */
#define   US_MR_PAR_EVEN (0x0u << 9) /**< \brief (US_MR) Even parity */
#define   US_MR_PAR_ODD (0x1u << 9) /**< \brief (US_MR) Odd parity */
#define   US_MR_PAR_SPACE (0x2u << 9) /**< \brief (US_MR) Parity forced to 0 (Space) */
#define   US_MR_PAR_MARK (0x3u << 9) /**< \brief (US_MR) Parity forced to 1 (Mark) */
#define   US_MR_PAR_NO (0x4u << 9) /**< \brief (US_MR) No parity */
#define   US_MR_PAR_MULTIDROP (0x6u << 9) /**< \brief (US_MR) Multidrop mode */
#define US_MR_NBSTOP_Pos 12
#define US_MR_NBSTOP_Msk (0x3u << US_MR_NBSTOP_Pos) /**< \brief (US_MR) Number of Stop Bits */
#define   US_MR_NBSTOP_1_BIT (0x0u << 12) /**< \brief (US_MR) 1 stop bit */
#define   US_MR_NBSTOP_1_5_BIT (0x1u << 12) /**< \brief (US_MR) 1.5 stop bit (SYNC = 0) or reserved (SYNC = 1) */
#define   US_MR_NBSTOP_2_BIT (0x2u << 12) /**< \brief (US_MR) 2 stop bits */
#define US_MR_CHMODE_Pos 14
#define US_MR_CHMODE_Msk (0x3u << US_MR_CHMODE_Pos) /**< \brief (US_MR) Channel Mode */
#define   US_MR_CHMODE_NORMAL (0x0u << 14) /**< \brief (US_MR) Normal Mode */
#define   US_MR_CHMODE_AUTOMATIC (0x1u << 14) /**< \brief (US_MR) Automatic Echo. Receiver input is connected to the TXD pin. */
#define   US_MR_CHMODE_LOCAL_LOOPBACK (0x2u << 14) /**< \brief (US_MR) Local Loopback. Transmitter output is connected to the Receiver Input. */
#define   US_MR_CHMODE_REMOTE_LOOPBACK (0x3u << 14) /**< \brief (US_MR) Remote Loopback. RXD pin is internally connected to the TXD pin. */
#define US_MR_MSBF (0x1u << 16) /**< \brief (US_MR) Bit Order */
#define US_MR_CPOL (0x1u << 16) /**< \brief (US_MR) SPI Clock Polarity */
#define US_MR_MODE9 (0x1u << 17) /**< \brief (US_MR) 9-bit Character Length */
#define US_MR_CLKO (0x1u << 18) /**< \brief (US_MR) Clock Output Select */
#define US_MR_OVER (0x1u << 19) /**< \brief (US_MR) Oversampling Mode */
#define US_MR_INACK (0x1u << 20) /**< \brief (US_MR) Inhibit Non Acknowledge */
#define US_MR_DSNACK (0x1u << 21) /**< \brief (US_MR) Disable Successive NACK */
#define US_MR_VAR_SYNC (0x1u << 22) /**< \brief (US_MR) Variable Synchronization of Command/Data Sync Start Frame Delimiter */
#define US_MR_INVDATA (0x1u << 23) /**< \brief (US_MR) INverted Data */
#define US_MR_MAX_ITERATION_Pos 24
#define US_MR_MAX_ITERATION_Msk (0x7u << US_MR_MAX_ITERATION_Pos) /**< \brief (US_MR)  */
#define US_MR_MAX_ITERATION(value) ((US_MR_MAX_ITERATION_Msk & ((value) << US_MR_MAX_ITERATION_Pos)))
#define US_MR_FILTER (0x1u << 28) /**< \brief (US_MR) Infrared Receive Line Filter */
#define US_MR_MAN (0x1u << 29) /**< \brief (US_MR) Manchester Encoder/Decoder Enable */
#define US_MR_MODSYNC (0x1u << 30) /**< \brief (US_MR) Manchester Synchronization Mode */
#define US_MR_ONEBIT (0x1u << 31) /**< \brief (US_MR) Start Frame Delimiter Selector */
/* -------- US_IER : (USART Offset: 0x0008) Interrupt Enable Register -------- */
#define US_IER_RXRDY (0x1u << 0) /**< \brief (US_IER) RXRDY Interrupt Enable */
#define US_IER_TXRDY (0x1u << 1) /**< \brief (US_IER) TXRDY Interrupt Enable */
#define US_IER_RXBRK (0x1u << 2) /**< \brief (US_IER) Receiver Break Interrupt Enable */
#define US_IER_OVRE (0x1u << 5) /**< \brief (US_IER) Overrun Error Interrupt Enable */
#define US_IER_FRAME (0x1u << 6) /**< \brief (US_IER) Framing Error Interrupt Enable */
#define US_IER_PARE (0x1u << 7) /**< \brief (US_IER) Parity Error Interrupt Enable */
#define US_IER_TIMEOUT (0x1u << 8) /**< \brief (US_IER) Time-out Interrupt Enable */
#define US_IER_TXEMPTY (0x1u << 9) /**< \brief (US_IER) TXEMPTY Interrupt Enable */
#define US_IER_ITER (0x1u << 10) /**< \brief (US_IER) Max number of Repetitions Reached */
#define US_IER_UNRE (0x1u << 10) /**< \brief (US_IER) SPI Underrun Error */
#define US_IER_NACK (0x1u << 13) /**< \brief (US_IER) Non Acknowledge Interrupt Enable */
#define US_IER_LINBK (0x1u << 13) /**< \brief (US_IER) LIN Break Sent or LIN Break Received Interrupt Enable */
#define US_IER_LINID (0x1u << 14) /**< \brief (US_IER) LIN Identifier Sent or LIN Identifier Received Interrupt Enable */
#define US_IER_LINTC (0x1u << 15) /**< \brief (US_IER) LIN Transfer Completed Interrupt Enable */
#define US_IER_CTSIC (0x1u << 19) /**< \brief (US_IER) Clear to Send Input Change Interrupt Enable */
#define US_IER_MANE (0x1u << 24) /**< \brief (US_IER) Manchester Error Interrupt Enable */
#define US_IER_LINBE (0x1u << 25) /**< \brief (US_IER) LIN Bus Error Interrupt Enable */
#define US_IER_LINISFE (0x1u << 26) /**< \brief (US_IER) LIN Inconsistent Synch Field Error Interrupt Enable */
#define US_IER_LINIPE (0x1u << 27) /**< \brief (US_IER) LIN Identifier Parity Interrupt Enable */
#define US_IER_LINCE (0x1u << 28) /**< \brief (US_IER) LIN Checksum Error Interrupt Enable */
#define US_IER_LINSNRE (0x1u << 29) /**< \brief (US_IER) LIN Slave Not Responding Error Interrupt Enable */
/* -------- US_IDR : (USART Offset: 0x000C) Interrupt Disable Register -------- */
#define US_IDR_RXRDY (0x1u << 0) /**< \brief (US_IDR) RXRDY Interrupt Disable */
#define US_IDR_TXRDY (0x1u << 1) /**< \brief (US_IDR) TXRDY Interrupt Disable */
#define US_IDR_RXBRK (0x1u << 2) /**< \brief (US_IDR) Receiver Break Interrupt Disable */
#define US_IDR_OVRE (0x1u << 5) /**< \brief (US_IDR) Overrun Error Interrupt Disable */
#define US_IDR_FRAME (0x1u << 6) /**< \brief (US_IDR) Framing Error Interrupt Disable */
#define US_IDR_PARE (0x1u << 7) /**< \brief (US_IDR) Parity Error Interrupt Disable */
#define US_IDR_TIMEOUT (0x1u << 8) /**< \brief (US_IDR) Time-out Interrupt Disable */
#define US_IDR_TXEMPTY (0x1u << 9) /**< \brief (US_IDR) TXEMPTY Interrupt Disable */
#define US_IDR_ITER (0x1u << 10) /**< \brief (US_IDR) Max number of Repetitions Reached Disable */
#define US_IDR_UNRE (0x1u << 10) /**< \brief (US_IDR) SPI Underrun Error Disable */
#define US_IDR_NACK (0x1u << 13) /**< \brief (US_IDR) Non Acknowledge Interrupt Disable */
#define US_IDR_LINBK (0x1u << 13) /**< \brief (US_IDR) LIN Break Sent or LIN Break Received Interrupt Disable */
#define US_IDR_LINID (0x1u << 14) /**< \brief (US_IDR) LIN Identifier Sent or LIN Identifier Received Interrupt Disable */
#define US_IDR_LINTC (0x1u << 15) /**< \brief (US_IDR) LIN Transfer Completed Interrupt Disable */
#define US_IDR_CTSIC (0x1u << 19) /**< \brief (US_IDR) Clear to Send Input Change Interrupt Disable */
#define US_IDR_MANE (0x1u << 24) /**< \brief (US_IDR) Manchester Error Interrupt Disable */
#define US_IDR_LINBE (0x1u << 25) /**< \brief (US_IDR) LIN Bus Error Interrupt Disable */
#define US_IDR_LINISFE (0x1u << 26) /**< \brief (US_IDR) LIN Inconsistent Synch Field Error Interrupt Disable */
#define US_IDR_LINIPE (0x1u << 27) /**< \brief (US_IDR) LIN Identifier Parity Interrupt Disable */
#define US_IDR_LINCE (0x1u << 28) /**< \brief (US_IDR) LIN Checksum Error Interrupt Disable */
#define US_IDR_LINSNRE (0x1u << 29) /**< \brief (US_IDR) LIN Slave Not Responding Error Interrupt Disable */
/* -------- US_IMR : (USART Offset: 0x0010) Interrupt Mask Register -------- */
#define US_IMR_RXRDY (0x1u << 0) /**< \brief (US_IMR) RXRDY Interrupt Mask */
#define US_IMR_TXRDY (0x1u << 1) /**< \brief (US_IMR) TXRDY Interrupt Mask */
#define US_IMR_RXBRK (0x1u << 2) /**< \brief (US_IMR) Receiver Break Interrupt Mask */
#define US_IMR_OVRE (0x1u << 5) /**< \brief (US_IMR) Overrun Error Interrupt Mask */
#define US_IMR_FRAME (0x1u << 6) /**< \brief (US_IMR) Framing Error Interrupt Mask */
#define US_IMR_PARE (0x1u << 7) /**< \brief (US_IMR) Parity Error Interrupt Mask */
#define US_IMR_TIMEOUT (0x1u << 8) /**< \brief (US_IMR) Time-out Interrupt Mask */
#define US_IMR_TXEMPTY (0x1u << 9) /**< \brief (US_IMR) TXEMPTY Interrupt Mask */
#define US_IMR_ITER (0x1u << 10) /**< \brief (US_IMR) Max number of Repetitions Reached Mask */
#define US_IMR_UNRE (0x1u << 10) /**< \brief (US_IMR) SPI Underrun Error Mask */
#define US_IMR_NACK (0x1u << 13) /**< \brief (US_IMR) Non Acknowledge Interrupt Mask */
#define US_IMR_LINBK (0x1u << 13) /**< \brief (US_IMR) LIN Break Sent or LIN Break Received Interrupt Mask */
#define US_IMR_LINID (0x1u << 14) /**< \brief (US_IMR) LIN Identifier Sent or LIN Identifier Received Interrupt Mask */
#define US_IMR_LINTC (0x1u << 15) /**< \brief (US_IMR) LIN Transfer Completed Interrupt Mask */
#define US_IMR_CTSIC (0x1u << 19) /**< \brief (US_IMR) Clear to Send Input Change Interrupt Mask */
#define US_IMR_MANE (0x1u << 24) /**< \brief (US_IMR) Manchester Error Interrupt Mask */
#define US_IMR_LINBE (0x1u << 25) /**< \brief (US_IMR) LIN Bus Error Interrupt Mask */
#define US_IMR_LINISFE (0x1u << 26) /**< \brief (US_IMR) LIN Inconsistent Synch Field Error Interrupt Mask */
#define US_IMR_LINIPE (0x1u << 27) /**< \brief (US_IMR) LIN Identifier Parity Interrupt Mask */
#define US_IMR_LINCE (0x1u << 28) /**< \brief (US_IMR) LIN Checksum Error Interrupt Mask */
#define US_IMR_LINSNRE (0x1u << 29) /**< \brief (US_IMR) LIN Slave Not Responding Error Interrupt Mask */
/* -------- US_CSR : (USART Offset: 0x0014) Channel Status Register -------- */
#define US_CSR_RXRDY (0x1u << 0) /**< \brief (US_CSR) Receiver Ready */
#define US_CSR_TXRDY (0x1u << 1) /**< \brief (US_CSR) Transmitter Ready */
#define US_CSR_RXBRK (0x1u << 2) /**< \brief (US_CSR) Break Received/End of Break */
#define US_CSR_OVRE (0x1u << 5) /**< \brief (US_CSR) Overrun Error */
#define US_CSR_FRAME (0x1u << 6) /**< \brief (US_CSR) Framing Error */
#define US_CSR_PARE (0x1u << 7) /**< \brief (US_CSR) Parity Error */
#define US_CSR_TIMEOUT (0x1u << 8) /**< \brief (US_CSR) Receiver Time-out */
#define US_CSR_TXEMPTY (0x1u << 9) /**< \brief (US_CSR) Transmitter Empty */
#define US_CSR_ITER (0x1u << 10) /**< \brief (US_CSR) Max number of Repetitions Reached */
#define US_CSR_UNRE (0x1u << 10) /**< \brief (US_CSR) SPI Underrun Error */
#define US_CSR_NACK (0x1u << 13) /**< \brief (US_CSR) Non Acknowledge Interrupt */
#define US_CSR_LINBK (0x1u << 13) /**< \brief (US_CSR) LIN Break Sent or LIN Break Received */
#define US_CSR_LINID (0x1u << 14) /**< \brief (US_CSR) LIN Identifier Sent or LIN Identifier Received */
#define US_CSR_LINTC (0x1u << 15) /**< \brief (US_CSR) LIN Transfer Completed */
#define US_CSR_CTSIC (0x1u << 19) /**< \brief (US_CSR) Clear to Send Input Change Flag */
#define US_CSR_CTS (0x1u << 23) /**< \brief (US_CSR) Image of CTS Input */
#define US_CSR_LINBLS (0x1u << 23) /**< \brief (US_CSR) LIN Bus Line Status */
#define US_CSR_MANERR (0x1u << 24) /**< \brief (US_CSR) Manchester Error */
#define US_CSR_LINBE (0x1u << 25) /**< \brief (US_CSR) LIN Bit Error */
#define US_CSR_LINISFE (0x1u << 26) /**< \brief (US_CSR) LIN Inconsistent Synch Field Error */
#define US_CSR_LINIPE (0x1u << 27) /**< \brief (US_CSR) LIN Identifier Parity Error */
#define US_CSR_LINCE (0x1u << 28) /**< \brief (US_CSR) LIN Checksum Error */
#define US_CSR_LINSNRE (0x1u << 29) /**< \brief (US_CSR) LIN Slave Not Responding Error */
/* -------- US_RHR : (USART Offset: 0x0018) Receiver Holding Register -------- */
#define US_RHR_RXCHR_Pos 0
#define US_RHR_RXCHR_Msk (0x1ffu << US_RHR_RXCHR_Pos) /**< \brief (US_RHR) Received Character */
#define US_RHR_RXSYNH (0x1u << 15) /**< \brief (US_RHR) Received Sync */
/* -------- US_THR : (USART Offset: 0x001C) Transmitter Holding Register -------- */
#define US_THR_TXCHR_Pos 0
#define US_THR_TXCHR_Msk (0x1ffu << US_THR_TXCHR_Pos) /**< \brief (US_THR) Character to be Transmitted */
#define US_THR_TXCHR(value) ((US_THR_TXCHR_Msk & ((value) << US_THR_TXCHR_Pos)))
#define US_THR_TXSYNH (0x1u << 15) /**< \brief (US_THR) Sync Field to be transmitted */
/* -------- US_BRGR : (USART Offset: 0x0020) Baud Rate Generator Register -------- */
#define US_BRGR_CD_Pos 0
#define US_BRGR_CD_Msk (0xffffu << US_BRGR_CD_Pos) /**< \brief (US_BRGR) Clock Divider */
#define US_BRGR_CD(value) ((US_BRGR_CD_Msk & ((value) << US_BRGR_CD_Pos)))
#define US_BRGR_FP_Pos 16
#define US_BRGR_FP_Msk (0x7u << US_BRGR_FP_Pos) /**< \brief (US_BRGR) Fractional Part */
#define US_BRGR_FP(value) ((US_BRGR_FP_Msk & ((value) << US_BRGR_FP_Pos)))
/* -------- US_RTOR : (USART Offset: 0x0024) Receiver Time-out Register -------- */
#define US_RTOR_TO_Pos 0
#define US_RTOR_TO_Msk (0x1ffffu << US_RTOR_TO_Pos) /**< \brief (US_RTOR) Time-out Value */
#define US_RTOR_TO(value) ((US_RTOR_TO_Msk & ((value) << US_RTOR_TO_Pos)))
/* -------- US_TTGR : (USART Offset: 0x0028) Transmitter Timeguard Register -------- */
#define US_TTGR_TG_Pos 0
#define US_TTGR_TG_Msk (0xffu << US_TTGR_TG_Pos) /**< \brief (US_TTGR) Timeguard Value */
#define US_TTGR_TG(value) ((US_TTGR_TG_Msk & ((value) << US_TTGR_TG_Pos)))
/* -------- US_FIDI : (USART Offset: 0x0040) FI DI Ratio Register -------- */
#define US_FIDI_FI_DI_RATIO_Pos 0
#define US_FIDI_FI_DI_RATIO_Msk (0x7ffu << US_FIDI_FI_DI_RATIO_Pos) /**< \brief (US_FIDI) FI Over DI Ratio Value */
#define US_FIDI_FI_DI_RATIO(value) ((US_FIDI_FI_DI_RATIO_Msk & ((value) << US_FIDI_FI_DI_RATIO_Pos)))
/* -------- US_NER : (USART Offset: 0x0044) Number of Errors Register -------- */
#define US_NER_NB_ERRORS_Pos 0
#define US_NER_NB_ERRORS_Msk (0xffu << US_NER_NB_ERRORS_Pos) /**< \brief (US_NER) Number of Errors */
/* -------- US_IF : (USART Offset: 0x004C) IrDA Filter Register -------- */
#define US_IF_IRDA_FILTER_Pos 0
#define US_IF_IRDA_FILTER_Msk (0xffu << US_IF_IRDA_FILTER_Pos) /**< \brief (US_IF) IrDA Filter */
#define US_IF_IRDA_FILTER(value) ((US_IF_IRDA_FILTER_Msk & ((value) << US_IF_IRDA_FILTER_Pos)))
/* -------- US_MAN : (USART Offset: 0x0050) Manchester Encoder Decoder Register -------- */
#define US_MAN_TX_PL_Pos 0
#define US_MAN_TX_PL_Msk (0xfu << US_MAN_TX_PL_Pos) /**< \brief (US_MAN) Transmitter Preamble Length */
#define US_MAN_TX_PL(value) ((US_MAN_TX_PL_Msk & ((value) << US_MAN_TX_PL_Pos)))
#define US_MAN_TX_PP_Pos 8
#define US_MAN_TX_PP_Msk (0x3u << US_MAN_TX_PP_Pos) /**< \brief (US_MAN) Transmitter Preamble Pattern */
#define   US_MAN_TX_PP_ALL_ONE (0x0u << 8) /**< \brief (US_MAN) The preamble is composed of '1's */
#define   US_MAN_TX_PP_ALL_ZERO (0x1u << 8) /**< \brief (US_MAN) The preamble is composed of '0's */
#define   US_MAN_TX_PP_ZERO_ONE (0x2u << 8) /**< \brief (US_MAN) The preamble is composed of '01's */
#define   US_MAN_TX_PP_ONE_ZERO (0x3u << 8) /**< \brief (US_MAN) The preamble is composed of '10's */
#define US_MAN_TX_MPOL (0x1u << 12) /**< \brief (US_MAN) Transmitter Manchester Polarity */
#define US_MAN_RX_PL_Pos 16
#define US_MAN_RX_PL_Msk (0xfu << US_MAN_RX_PL_Pos) /**< \brief (US_MAN) Receiver Preamble Length */
#define US_MAN_RX_PL(value) ((US_MAN_RX_PL_Msk & ((value) << US_MAN_RX_PL_Pos)))
#define US_MAN_RX_PP_Pos 24
#define US_MAN_RX_PP_Msk (0x3u << US_MAN_RX_PP_Pos) /**< \brief (US_MAN) Receiver Preamble Pattern detected */
#define   US_MAN_RX_PP_ALL_ONE (0x0u << 24) /**< \brief (US_MAN) The preamble is composed of '1's */
#define   US_MAN_RX_PP_ALL_ZERO (0x1u << 24) /**< \brief (US_MAN) The preamble is composed of '0's */
#define   US_MAN_RX_PP_ZERO_ONE (0x2u << 24) /**< \brief (US_MAN) The preamble is composed of '01's */
#define   US_MAN_RX_PP_ONE_ZERO (0x3u << 24) /**< \brief (US_MAN) The preamble is composed of '10's */
#define US_MAN_RX_MPOL (0x1u << 28) /**< \brief (US_MAN) Receiver Manchester Polarity */
#define US_MAN_STUCKTO1 (0x1u << 29) /**< \brief (US_MAN)  */
#define US_MAN_DRIFT (0x1u << 30) /**< \brief (US_MAN) Drift compensation */
/* -------- US_LINMR : (USART Offset: 0x0054) LIN Mode Register -------- */
#define US_LINMR_NACT_Pos 0
#define US_LINMR_NACT_Msk (0x3u << US_LINMR_NACT_Pos) /**< \brief (US_LINMR) LIN Node Action */
#define   US_LINMR_NACT_PUBLISH (0x0u << 0) /**< \brief (US_LINMR) The USART transmits the response. */
#define   US_LINMR_NACT_SUBSCRIBE (0x1u << 0) /**< \brief (US_LINMR) The USART receives the response. */
#define   US_LINMR_NACT_IGNORE (0x2u << 0) /**< \brief (US_LINMR) The USART does not transmit and does not receive the response. */
#define US_LINMR_PARDIS (0x1u << 2) /**< \brief (US_LINMR) Parity Disable */
#define US_LINMR_CHKDIS (0x1u << 3) /**< \brief (US_LINMR) Checksum Disable */
#define US_LINMR_CHKTYP (0x1u << 4) /**< \brief (US_LINMR) Checksum Type */
#define US_LINMR_DLM (0x1u << 5) /**< \brief (US_LINMR) Data Length Mode */
#define US_LINMR_FSDIS (0x1u << 6) /**< \brief (US_LINMR) Frame Slot Mode Disable */
#define US_LINMR_WKUPTYP (0x1u << 7) /**< \brief (US_LINMR) Wakeup Signal Type */
#define US_LINMR_DLC_Pos 8
#define US_LINMR_DLC_Msk (0xffu << US_LINMR_DLC_Pos) /**< \brief (US_LINMR) Data Length Control */
#define US_LINMR_DLC(value) ((US_LINMR_DLC_Msk & ((value) << US_LINMR_DLC_Pos)))
#define US_LINMR_PDCM (0x1u << 16) /**< \brief (US_LINMR) DMAC Mode */
/* -------- US_LINIR : (USART Offset: 0x0058) LIN Identifier Register -------- */
#define US_LINIR_IDCHR_Pos 0
#define US_LINIR_IDCHR_Msk (0xffu << US_LINIR_IDCHR_Pos) /**< \brief (US_LINIR) Identifier Character */
#define US_LINIR_IDCHR(value) ((US_LINIR_IDCHR_Msk & ((value) << US_LINIR_IDCHR_Pos)))
/* -------- US_WPMR : (USART Offset: 0xE4) Write Protect Mode Register -------- */
#define US_WPMR_WPEN (0x1u << 0) /**< \brief (US_WPMR) Write Protect Enable */
#define US_WPMR_WPKEY_Pos 8
#define US_WPMR_WPKEY_Msk (0xffffffu << US_WPMR_WPKEY_Pos) /**< \brief (US_WPMR) Write Protect KEY */
#define US_WPMR_WPKEY(value) ((US_WPMR_WPKEY_Msk & ((value) << US_WPMR_WPKEY_Pos)))
/* -------- US_WPSR : (USART Offset: 0xE8) Write Protect Status Register -------- */
#define US_WPSR_WPVS (0x1u << 0) /**< \brief (US_WPSR) Write Protect Violation Status */
#define US_WPSR_WPVSRC_Pos 8
#define US_WPSR_WPVSRC_Msk (0xffffu << US_WPSR_WPVSRC_Pos) /**< \brief (US_WPSR) Write Protect Violation Source */

/*@}*/

/* ============================================================================= */
/**  SOFTWARE API DEFINITION FOR Watchdog Timer */
/* ============================================================================= */
/** \addtogroup SAM9N12_WDT Watchdog Timer */
/*@{*/

#ifndef __ASSEMBLY__
/** \brief Wdt hardware registers */
typedef struct {
  WoReg WDT_CR; /**< \brief (Wdt Offset: 0x00) Control Register */
  RwReg WDT_MR; /**< \brief (Wdt Offset: 0x04) Mode Register */
  RoReg WDT_SR; /**< \brief (Wdt Offset: 0x08) Status Register */
} Wdt;
#endif /* __ASSEMBLY__ */
/* -------- WDT_CR : (WDT Offset: 0x00) Control Register -------- */
#define WDT_CR_WDRSTT (0x1u << 0) /**< \brief (WDT_CR) Watchdog Restart */
#define WDT_CR_KEY_Pos 24
#define WDT_CR_KEY_Msk (0xffu << WDT_CR_KEY_Pos) /**< \brief (WDT_CR) Password */
#define WDT_CR_KEY(value) ((WDT_CR_KEY_Msk & ((value) << WDT_CR_KEY_Pos)))
/* -------- WDT_MR : (WDT Offset: 0x04) Mode Register -------- */
#define WDT_MR_WDV_Pos 0
#define WDT_MR_WDV_Msk (0xfffu << WDT_MR_WDV_Pos) /**< \brief (WDT_MR) Watchdog Counter Value */
#define WDT_MR_WDV(value) ((WDT_MR_WDV_Msk & ((value) << WDT_MR_WDV_Pos)))
#define WDT_MR_WDFIEN (0x1u << 12) /**< \brief (WDT_MR) Watchdog Fault Interrupt Enable */
#define WDT_MR_WDRSTEN (0x1u << 13) /**< \brief (WDT_MR) Watchdog Reset Enable */
#define WDT_MR_WDRPROC (0x1u << 14) /**< \brief (WDT_MR) Watchdog Reset Processor */
#define WDT_MR_WDDIS (0x1u << 15) /**< \brief (WDT_MR) Watchdog Disable */
#define WDT_MR_WDD_Pos 16
#define WDT_MR_WDD_Msk (0xfffu << WDT_MR_WDD_Pos) /**< \brief (WDT_MR) Watchdog Delta Value */
#define WDT_MR_WDD(value) ((WDT_MR_WDD_Msk & ((value) << WDT_MR_WDD_Pos)))
#define WDT_MR_WDDBGHLT (0x1u << 28) /**< \brief (WDT_MR) Watchdog Debug Halt */
#define WDT_MR_WDIDLEHLT (0x1u << 29) /**< \brief (WDT_MR) Watchdog Idle Halt */
/* -------- WDT_SR : (WDT Offset: 0x08) Status Register -------- */
#define WDT_SR_WDUNF (0x1u << 0) /**< \brief (WDT_SR) Watchdog Underflow */
#define WDT_SR_WDERR (0x1u << 1) /**< \brief (WDT_SR) Watchdog Error */

/*@}*/

/*@}*/

/* ************************************************************************** */
/*   REGISTER ACCESS DEFINITIONS FOR SAM9N12 */
/* ************************************************************************** */
/** \addtogroup SAM9N12_reg Registers Access Definitions */
/*@{*/

/* ========== Register definition for SPI0 peripheral ========== */
#define REG_SPI0_CR            REG_ACCESS(WoReg, 0xF0000000U) /**< \brief (SPI0) Control Register */
#define REG_SPI0_MR            REG_ACCESS(RwReg, 0xF0000004U) /**< \brief (SPI0) Mode Register */
#define REG_SPI0_RDR           REG_ACCESS(RoReg, 0xF0000008U) /**< \brief (SPI0) Receive Data Register */
#define REG_SPI0_TDR           REG_ACCESS(WoReg, 0xF000000CU) /**< \brief (SPI0) Transmit Data Register */
#define REG_SPI0_SR            REG_ACCESS(RoReg, 0xF0000010U) /**< \brief (SPI0) Status Register */
#define REG_SPI0_IER           REG_ACCESS(WoReg, 0xF0000014U) /**< \brief (SPI0) Interrupt Enable Register */
#define REG_SPI0_IDR           REG_ACCESS(WoReg, 0xF0000018U) /**< \brief (SPI0) Interrupt Disable Register */
#define REG_SPI0_IMR           REG_ACCESS(RoReg, 0xF000001CU) /**< \brief (SPI0) Interrupt Mask Register */
#define REG_SPI0_CSR           REG_ACCESS(RwReg, 0xF0000030U) /**< \brief (SPI0) Chip Select Register */
#define REG_SPI0_WPMR          REG_ACCESS(RwReg, 0xF00000E4U) /**< \brief (SPI0) Write Protection Control Register */
#define REG_SPI0_WPSR          REG_ACCESS(RoReg, 0xF00000E8U) /**< \brief (SPI0) Write Protection Status Register */
/* ========== Register definition for SPI1 peripheral ========== */
#define REG_SPI1_CR            REG_ACCESS(WoReg, 0xF0004000U) /**< \brief (SPI1) Control Register */
#define REG_SPI1_MR            REG_ACCESS(RwReg, 0xF0004004U) /**< \brief (SPI1) Mode Register */
#define REG_SPI1_RDR           REG_ACCESS(RoReg, 0xF0004008U) /**< \brief (SPI1) Receive Data Register */
#define REG_SPI1_TDR           REG_ACCESS(WoReg, 0xF000400CU) /**< \brief (SPI1) Transmit Data Register */
#define REG_SPI1_SR            REG_ACCESS(RoReg, 0xF0004010U) /**< \brief (SPI1) Status Register */
#define REG_SPI1_IER           REG_ACCESS(WoReg, 0xF0004014U) /**< \brief (SPI1) Interrupt Enable Register */
#define REG_SPI1_IDR           REG_ACCESS(WoReg, 0xF0004018U) /**< \brief (SPI1) Interrupt Disable Register */
#define REG_SPI1_IMR           REG_ACCESS(RoReg, 0xF000401CU) /**< \brief (SPI1) Interrupt Mask Register */
#define REG_SPI1_CSR           REG_ACCESS(RwReg, 0xF0004030U) /**< \brief (SPI1) Chip Select Register */
#define REG_SPI1_WPMR          REG_ACCESS(RwReg, 0xF00040E4U) /**< \brief (SPI1) Write Protection Control Register */
#define REG_SPI1_WPSR          REG_ACCESS(RoReg, 0xF00040E8U) /**< \brief (SPI1) Write Protection Status Register */
/* ========== Register definition for HSMCI peripheral ========== */
#define REG_HSMCI_CR           REG_ACCESS(WoReg, 0xF0008000U) /**< \brief (HSMCI) Control Register */
#define REG_HSMCI_MR           REG_ACCESS(RwReg, 0xF0008004U) /**< \brief (HSMCI) Mode Register */
#define REG_HSMCI_DTOR         REG_ACCESS(RwReg, 0xF0008008U) /**< \brief (HSMCI) Data Timeout Register */
#define REG_HSMCI_SDCR         REG_ACCESS(RwReg, 0xF000800CU) /**< \brief (HSMCI) SD/SDIO Card Register */
#define REG_HSMCI_ARGR         REG_ACCESS(RwReg, 0xF0008010U) /**< \brief (HSMCI) Argument Register */
#define REG_HSMCI_CMDR         REG_ACCESS(WoReg, 0xF0008014U) /**< \brief (HSMCI) Command Register */
#define REG_HSMCI_BLKR         REG_ACCESS(RwReg, 0xF0008018U) /**< \brief (HSMCI) Block Register */
#define REG_HSMCI_CSTOR        REG_ACCESS(RwReg, 0xF000801CU) /**< \brief (HSMCI) Completion Signal Timeout Register */
#define REG_HSMCI_RSPR         REG_ACCESS(RoReg, 0xF0008020U) /**< \brief (HSMCI) Response Register */
#define REG_HSMCI_RDR          REG_ACCESS(RoReg, 0xF0008030U) /**< \brief (HSMCI) Receive Data Register */
#define REG_HSMCI_TDR          REG_ACCESS(WoReg, 0xF0008034U) /**< \brief (HSMCI) Transmit Data Register */
#define REG_HSMCI_SR           REG_ACCESS(RoReg, 0xF0008040U) /**< \brief (HSMCI) Status Register */
#define REG_HSMCI_IER          REG_ACCESS(WoReg, 0xF0008044U) /**< \brief (HSMCI) Interrupt Enable Register */
#define REG_HSMCI_IDR          REG_ACCESS(WoReg, 0xF0008048U) /**< \brief (HSMCI) Interrupt Disable Register */
#define REG_HSMCI_IMR          REG_ACCESS(RoReg, 0xF000804CU) /**< \brief (HSMCI) Interrupt Mask Register */
#define REG_HSMCI_DMA          REG_ACCESS(RwReg, 0xF0008050U) /**< \brief (HSMCI) DMA Configuration Register */
#define REG_HSMCI_CFG          REG_ACCESS(RwReg, 0xF0008054U) /**< \brief (HSMCI) Configuration Register */
#define REG_HSMCI_WPMR         REG_ACCESS(RwReg, 0xF00080E4U) /**< \brief (HSMCI) Write Protection Mode Register */
#define REG_HSMCI_WPSR         REG_ACCESS(RoReg, 0xF00080E8U) /**< \brief (HSMCI) Write Protection Status Register */
#define REG_HSMCI_FIFO         REG_ACCESS(RwReg, 0xF0008200U) /**< \brief (HSMCI) FIFO Memory Aperture0 */

/* ========== Register definition for TWI0 peripheral ========== */
#define REG_TWI0_CR            REG_ACCESS(WoReg, 0xF8010000U) /**< \brief (TWI0) Control Register */
#define REG_TWI0_MMR           REG_ACCESS(RwReg, 0xF8010004U) /**< \brief (TWI0) Master Mode Register */
#define REG_TWI0_SMR           REG_ACCESS(RwReg, 0xF8010008U) /**< \brief (TWI0) Slave Mode Register */
#define REG_TWI0_IADR          REG_ACCESS(RwReg, 0xF801000CU) /**< \brief (TWI0) Internal Address Register */
#define REG_TWI0_CWGR          REG_ACCESS(RwReg, 0xF8010010U) /**< \brief (TWI0) Clock Waveform Generator Register */
#define REG_TWI0_SR            REG_ACCESS(RoReg, 0xF8010020U) /**< \brief (TWI0) Status Register */
#define REG_TWI0_IER           REG_ACCESS(WoReg, 0xF8010024U) /**< \brief (TWI0) Interrupt Enable Register */
#define REG_TWI0_IDR           REG_ACCESS(WoReg, 0xF8010028U) /**< \brief (TWI0) Interrupt Disable Register */
#define REG_TWI0_IMR           REG_ACCESS(RoReg, 0xF801002CU) /**< \brief (TWI0) Interrupt Mask Register */
#define REG_TWI0_RHR           REG_ACCESS(RoReg, 0xF8010030U) /**< \brief (TWI0) Receive Holding Register */
#define REG_TWI0_THR           REG_ACCESS(WoReg, 0xF8010034U) /**< \brief (TWI0) Transmit Holding Register */
/* ========== Register definition for TWI1 peripheral ========== */
#define REG_TWI1_CR            REG_ACCESS(WoReg, 0xF8014000U) /**< \brief (TWI1) Control Register */
#define REG_TWI1_MMR           REG_ACCESS(RwReg, 0xF8014004U) /**< \brief (TWI1) Master Mode Register */
#define REG_TWI1_SMR           REG_ACCESS(RwReg, 0xF8014008U) /**< \brief (TWI1) Slave Mode Register */
#define REG_TWI1_IADR          REG_ACCESS(RwReg, 0xF801400CU) /**< \brief (TWI1) Internal Address Register */
#define REG_TWI1_CWGR          REG_ACCESS(RwReg, 0xF8014010U) /**< \brief (TWI1) Clock Waveform Generator Register */
#define REG_TWI1_SR            REG_ACCESS(RoReg, 0xF8014020U) /**< \brief (TWI1) Status Register */
#define REG_TWI1_IER           REG_ACCESS(WoReg, 0xF8014024U) /**< \brief (TWI1) Interrupt Enable Register */
#define REG_TWI1_IDR           REG_ACCESS(WoReg, 0xF8014028U) /**< \brief (TWI1) Interrupt Disable Register */
#define REG_TWI1_IMR           REG_ACCESS(RoReg, 0xF801402CU) /**< \brief (TWI1) Interrupt Mask Register */
#define REG_TWI1_RHR           REG_ACCESS(RoReg, 0xF8014030U) /**< \brief (TWI1) Receive Holding Register */
#define REG_TWI1_THR           REG_ACCESS(WoReg, 0xF8014034U) /**< \brief (TWI1) Transmit Holding Register */
/* ========== Register definition for USART0 peripheral ========== */
#define REG_USART0_CR          REG_ACCESS(WoReg, 0xF801C000U) /**< \brief (USART0) Control Register */
#define REG_USART0_MR          REG_ACCESS(RwReg, 0xF801C004U) /**< \brief (USART0) Mode Register */
#define REG_USART0_IER         REG_ACCESS(WoReg, 0xF801C008U) /**< \brief (USART0) Interrupt Enable Register */
#define REG_USART0_IDR         REG_ACCESS(WoReg, 0xF801C00CU) /**< \brief (USART0) Interrupt Disable Register */
#define REG_USART0_IMR         REG_ACCESS(RoReg, 0xF801C010U) /**< \brief (USART0) Interrupt Mask Register */
#define REG_USART0_CSR         REG_ACCESS(RoReg, 0xF801C014U) /**< \brief (USART0) Channel Status Register */
#define REG_USART0_RHR         REG_ACCESS(RoReg, 0xF801C018U) /**< \brief (USART0) Receiver Holding Register */
#define REG_USART0_THR         REG_ACCESS(WoReg, 0xF801C01CU) /**< \brief (USART0) Transmitter Holding Register */
#define REG_USART0_BRGR        REG_ACCESS(RwReg, 0xF801C020U) /**< \brief (USART0) Baud Rate Generator Register */
#define REG_USART0_RTOR        REG_ACCESS(RwReg, 0xF801C024U) /**< \brief (USART0) Receiver Time-out Register */
#define REG_USART0_TTGR        REG_ACCESS(RwReg, 0xF801C028U) /**< \brief (USART0) Transmitter Timeguard Register */
#define REG_USART0_FIDI        REG_ACCESS(RwReg, 0xF801C040U) /**< \brief (USART0) FI DI Ratio Register */
#define REG_USART0_NER         REG_ACCESS(RoReg, 0xF801C044U) /**< \brief (USART0) Number of Errors Register */
#define REG_USART0_IF          REG_ACCESS(RwReg, 0xF801C04CU) /**< \brief (USART0) IrDA Filter Register */
#define REG_USART0_MAN         REG_ACCESS(RwReg, 0xF801C050U) /**< \brief (USART0) Manchester Encoder Decoder Register */
#define REG_USART0_LINMR       REG_ACCESS(RwReg, 0xF801C054U) /**< \brief (USART0) LIN Mode Register */
#define REG_USART0_LINIR       REG_ACCESS(RwReg, 0xF801C058U) /**< \brief (USART0) LIN Identifier Register */
#define REG_USART0_WPMR        REG_ACCESS(RwReg, 0xF801C0E4U) /**< \brief (USART0) Write Protect Mode Register */
#define REG_USART0_WPSR        REG_ACCESS(RoReg, 0xF801C0E8U) /**< \brief (USART0) Write Protect Status Register */
/* ========== Register definition for USART1 peripheral ========== */
#define REG_USART1_CR          REG_ACCESS(WoReg, 0xF8020000U) /**< \brief (USART1) Control Register */
#define REG_USART1_MR          REG_ACCESS(RwReg, 0xF8020004U) /**< \brief (USART1) Mode Register */
#define REG_USART1_IER         REG_ACCESS(WoReg, 0xF8020008U) /**< \brief (USART1) Interrupt Enable Register */
#define REG_USART1_IDR         REG_ACCESS(WoReg, 0xF802000CU) /**< \brief (USART1) Interrupt Disable Register */
#define REG_USART1_IMR         REG_ACCESS(RoReg, 0xF8020010U) /**< \brief (USART1) Interrupt Mask Register */
#define REG_USART1_CSR         REG_ACCESS(RoReg, 0xF8020014U) /**< \brief (USART1) Channel Status Register */
#define REG_USART1_RHR         REG_ACCESS(RoReg, 0xF8020018U) /**< \brief (USART1) Receiver Holding Register */
#define REG_USART1_THR         REG_ACCESS(WoReg, 0xF802001CU) /**< \brief (USART1) Transmitter Holding Register */
#define REG_USART1_BRGR        REG_ACCESS(RwReg, 0xF8020020U) /**< \brief (USART1) Baud Rate Generator Register */
#define REG_USART1_RTOR        REG_ACCESS(RwReg, 0xF8020024U) /**< \brief (USART1) Receiver Time-out Register */
#define REG_USART1_TTGR        REG_ACCESS(RwReg, 0xF8020028U) /**< \brief (USART1) Transmitter Timeguard Register */
#define REG_USART1_FIDI        REG_ACCESS(RwReg, 0xF8020040U) /**< \brief (USART1) FI DI Ratio Register */
#define REG_USART1_NER         REG_ACCESS(RoReg, 0xF8020044U) /**< \brief (USART1) Number of Errors Register */
#define REG_USART1_IF          REG_ACCESS(RwReg, 0xF802004CU) /**< \brief (USART1) IrDA Filter Register */
#define REG_USART1_MAN         REG_ACCESS(RwReg, 0xF8020050U) /**< \brief (USART1) Manchester Encoder Decoder Register */
#define REG_USART1_LINMR       REG_ACCESS(RwReg, 0xF8020054U) /**< \brief (USART1) LIN Mode Register */
#define REG_USART1_LINIR       REG_ACCESS(RwReg, 0xF8020058U) /**< \brief (USART1) LIN Identifier Register */
#define REG_USART1_WPMR        REG_ACCESS(RwReg, 0xF80200E4U) /**< \brief (USART1) Write Protect Mode Register */
#define REG_USART1_WPSR        REG_ACCESS(RoReg, 0xF80200E8U) /**< \brief (USART1) Write Protect Status Register */
/* ========== Register definition for USART2 peripheral ========== */
#define REG_USART2_CR          REG_ACCESS(WoReg, 0xF8024000U) /**< \brief (USART2) Control Register */
#define REG_USART2_MR          REG_ACCESS(RwReg, 0xF8024004U) /**< \brief (USART2) Mode Register */
#define REG_USART2_IER         REG_ACCESS(WoReg, 0xF8024008U) /**< \brief (USART2) Interrupt Enable Register */
#define REG_USART2_IDR         REG_ACCESS(WoReg, 0xF802400CU) /**< \brief (USART2) Interrupt Disable Register */
#define REG_USART2_IMR         REG_ACCESS(RoReg, 0xF8024010U) /**< \brief (USART2) Interrupt Mask Register */
#define REG_USART2_CSR         REG_ACCESS(RoReg, 0xF8024014U) /**< \brief (USART2) Channel Status Register */
#define REG_USART2_RHR         REG_ACCESS(RoReg, 0xF8024018U) /**< \brief (USART2) Receiver Holding Register */
#define REG_USART2_THR         REG_ACCESS(WoReg, 0xF802401CU) /**< \brief (USART2) Transmitter Holding Register */
#define REG_USART2_BRGR        REG_ACCESS(RwReg, 0xF8024020U) /**< \brief (USART2) Baud Rate Generator Register */
#define REG_USART2_RTOR        REG_ACCESS(RwReg, 0xF8024024U) /**< \brief (USART2) Receiver Time-out Register */
#define REG_USART2_TTGR        REG_ACCESS(RwReg, 0xF8024028U) /**< \brief (USART2) Transmitter Timeguard Register */
#define REG_USART2_FIDI        REG_ACCESS(RwReg, 0xF8024040U) /**< \brief (USART2) FI DI Ratio Register */
#define REG_USART2_NER         REG_ACCESS(RoReg, 0xF8024044U) /**< \brief (USART2) Number of Errors Register */
#define REG_USART2_IF          REG_ACCESS(RwReg, 0xF802404CU) /**< \brief (USART2) IrDA Filter Register */
#define REG_USART2_MAN         REG_ACCESS(RwReg, 0xF8024050U) /**< \brief (USART2) Manchester Encoder Decoder Register */
#define REG_USART2_LINMR       REG_ACCESS(RwReg, 0xF8024054U) /**< \brief (USART2) LIN Mode Register */
#define REG_USART2_LINIR       REG_ACCESS(RwReg, 0xF8024058U) /**< \brief (USART2) LIN Identifier Register */
#define REG_USART2_WPMR        REG_ACCESS(RwReg, 0xF80240E4U) /**< \brief (USART2) Write Protect Mode Register */
#define REG_USART2_WPSR        REG_ACCESS(RoReg, 0xF80240E8U) /**< \brief (USART2) Write Protect Status Register */
/* ========== Register definition for USART3 peripheral ========== */
#define REG_USART3_CR          REG_ACCESS(WoReg, 0xF8028000U) /**< \brief (USART3) Control Register */
#define REG_USART3_MR          REG_ACCESS(RwReg, 0xF8028004U) /**< \brief (USART3) Mode Register */
#define REG_USART3_IER         REG_ACCESS(WoReg, 0xF8028008U) /**< \brief (USART3) Interrupt Enable Register */
#define REG_USART3_IDR         REG_ACCESS(WoReg, 0xF802800CU) /**< \brief (USART3) Interrupt Disable Register */
#define REG_USART3_IMR         REG_ACCESS(RoReg, 0xF8028010U) /**< \brief (USART3) Interrupt Mask Register */
#define REG_USART3_CSR         REG_ACCESS(RoReg, 0xF8028014U) /**< \brief (USART3) Channel Status Register */
#define REG_USART3_RHR         REG_ACCESS(RoReg, 0xF8028018U) /**< \brief (USART3) Receiver Holding Register */
#define REG_USART3_THR         REG_ACCESS(WoReg, 0xF802801CU) /**< \brief (USART3) Transmitter Holding Register */
#define REG_USART3_BRGR        REG_ACCESS(RwReg, 0xF8028020U) /**< \brief (USART3) Baud Rate Generator Register */
#define REG_USART3_RTOR        REG_ACCESS(RwReg, 0xF8028024U) /**< \brief (USART3) Receiver Time-out Register */
#define REG_USART3_TTGR        REG_ACCESS(RwReg, 0xF8028028U) /**< \brief (USART3) Transmitter Timeguard Register */
#define REG_USART3_FIDI        REG_ACCESS(RwReg, 0xF8028040U) /**< \brief (USART3) FI DI Ratio Register */
#define REG_USART3_NER         REG_ACCESS(RoReg, 0xF8028044U) /**< \brief (USART3) Number of Errors Register */
#define REG_USART3_IF          REG_ACCESS(RwReg, 0xF802804CU) /**< \brief (USART3) IrDA Filter Register */
#define REG_USART3_MAN         REG_ACCESS(RwReg, 0xF8028050U) /**< \brief (USART3) Manchester Encoder Decoder Register */
#define REG_USART3_LINMR       REG_ACCESS(RwReg, 0xF8028054U) /**< \brief (USART3) LIN Mode Register */
#define REG_USART3_LINIR       REG_ACCESS(RwReg, 0xF8028058U) /**< \brief (USART3) LIN Identifier Register */
#define REG_USART3_WPMR        REG_ACCESS(RwReg, 0xF80280E4U) /**< \brief (USART3) Write Protect Mode Register */
#define REG_USART3_WPSR        REG_ACCESS(RoReg, 0xF80280E8U) /**< \brief (USART3) Write Protect Status Register */

/* ========== Register definition for UART0 peripheral ========== */
#define REG_UART0_CR           REG_ACCESS(WoReg, 0xF8040000U) /**< \brief (UART0) Control Register */
#define REG_UART0_MR           REG_ACCESS(RwReg, 0xF8040004U) /**< \brief (UART0) Mode Register */
#define REG_UART0_IER          REG_ACCESS(WoReg, 0xF8040008U) /**< \brief (UART0) Interrupt Enable Register */
#define REG_UART0_IDR          REG_ACCESS(WoReg, 0xF804000CU) /**< \brief (UART0) Interrupt Disable Register */
#define REG_UART0_IMR          REG_ACCESS(RoReg, 0xF8040010U) /**< \brief (UART0) Interrupt Mask Register */
#define REG_UART0_SR           REG_ACCESS(RoReg, 0xF8040014U) /**< \brief (UART0) Status Register */
#define REG_UART0_RHR          REG_ACCESS(RoReg, 0xF8040018U) /**< \brief (UART0) Receive Holding Register */
#define REG_UART0_THR          REG_ACCESS(WoReg, 0xF804001CU) /**< \brief (UART0) Transmit Holding Register */
#define REG_UART0_BRGR         REG_ACCESS(RwReg, 0xF8040020U) /**< \brief (UART0) Baud Rate Generator Register */
/* ========== Register definition for UART1 peripheral ========== */
#define REG_UART1_CR           REG_ACCESS(WoReg, 0xF8044000U) /**< \brief (UART1) Control Register */
#define REG_UART1_MR           REG_ACCESS(RwReg, 0xF8044004U) /**< \brief (UART1) Mode Register */
#define REG_UART1_IER          REG_ACCESS(WoReg, 0xF8044008U) /**< \brief (UART1) Interrupt Enable Register */
#define REG_UART1_IDR          REG_ACCESS(WoReg, 0xF804400CU) /**< \brief (UART1) Interrupt Disable Register */
#define REG_UART1_IMR          REG_ACCESS(RoReg, 0xF8044010U) /**< \brief (UART1) Interrupt Mask Register */
#define REG_UART1_SR           REG_ACCESS(RoReg, 0xF8044014U) /**< \brief (UART1) Status Register */
#define REG_UART1_RHR          REG_ACCESS(RoReg, 0xF8044018U) /**< \brief (UART1) Receive Holding Register */
#define REG_UART1_THR          REG_ACCESS(WoReg, 0xF804401CU) /**< \brief (UART1) Transmit Holding Register */
#define REG_UART1_BRGR         REG_ACCESS(RwReg, 0xF8044020U) /**< \brief (UART1) Baud Rate Generator Register */
/* ========== Register definition for FUSE peripheral ========== */
#define REG_FUSE_CR            REG_ACCESS(WoReg, 0xFFFFDC00U) /**< \brief (FUSE) Fuse Control Register */
#define REG_FUSE_MR            REG_ACCESS(WoReg, 0xFFFFDC04U) /**< \brief (FUSE) Fuse Mode Register */
#define REG_FUSE_IR            REG_ACCESS(RwReg, 0xFFFFDC08U) /**< \brief (FUSE) Fuse Index Register */
#define REG_FUSE_DR            REG_ACCESS(WoReg, 0xFFFFDC0CU) /**< \brief (FUSE) Fuse Data Register */
#define REG_FUSE_SR            REG_ACCESS(RoReg, 0xFFFFDC10U) /**< \brief (FUSE) Fuse Status Register */
/* ========== Register definition for MATRIX peripheral ========== */
#define REG_MATRIX_MCFG        REG_ACCESS(RwReg, 0xFFFFDE00U) /**< \brief (MATRIX) Master Configuration Register */
#define REG_MATRIX_SCFG        REG_ACCESS(RwReg, 0xFFFFDE40U) /**< \brief (MATRIX) Slave Configuration Register */
#define REG_MATRIX_PRAS0       REG_ACCESS(RwReg, 0xFFFFDE80U) /**< \brief (MATRIX) Priority Register A for Slave 0 */
#define REG_MATRIX_PRAS1       REG_ACCESS(RwReg, 0xFFFFDE88U) /**< \brief (MATRIX) Priority Register A for Slave 1 */
#define REG_MATRIX_PRAS2       REG_ACCESS(RwReg, 0xFFFFDE90U) /**< \brief (MATRIX) Priority Register A for Slave 2 */
#define REG_MATRIX_PRAS3       REG_ACCESS(RwReg, 0xFFFFDE98U) /**< \brief (MATRIX) Priority Register A for Slave 3 */
#define REG_MATRIX_PRAS4       REG_ACCESS(RwReg, 0xFFFFDEA0U) /**< \brief (MATRIX) Priority Register A for Slave 4 */
#define REG_MATRIX_MRCR        REG_ACCESS(RwReg, 0xFFFFDF00U) /**< \brief (MATRIX) Master Remap Control Register */
#define REG_MATRIX_WPMR        REG_ACCESS(RwReg, 0xFFFFDFE4U) /**< \brief (MATRIX) Write Protect Mode Register */
#define REG_MATRIX_WPSR        REG_ACCESS(RoReg, 0xFFFFDFE8U) /**< \brief (MATRIX) Write Protect Status Register */
/* ========== Register definition for PMECC peripheral ========== */
#define REG_PMECC_CFG          REG_ACCESS(RwReg, 0xFFFFE000U) /**< \brief (PMECC) PMECC Configuration Register */
#define REG_PMECC_SAREA        REG_ACCESS(RwReg, 0xFFFFE004U) /**< \brief (PMECC) PMECC Spare Area Size Register */
#define REG_PMECC_SADDR        REG_ACCESS(RwReg, 0xFFFFE008U) /**< \brief (PMECC) PMECC Start Address Register */
#define REG_PMECC_EADDR        REG_ACCESS(RwReg, 0xFFFFE00CU) /**< \brief (PMECC) PMECC End Address Register */
#define REG_PMECC_CLK          REG_ACCESS(RwReg, 0xFFFFE010U) /**< \brief (PMECC) PMECC Clock Control Register */
#define REG_PMECC_CTRL         REG_ACCESS(WoReg, 0xFFFFE014U) /**< \brief (PMECC) PMECC Control Register */
#define REG_PMECC_SR           REG_ACCESS(RoReg, 0xFFFFE018U) /**< \brief (PMECC) PMECC Status Register */
#define REG_PMECC_IER          REG_ACCESS(WoReg, 0xFFFFE01CU) /**< \brief (PMECC) PMECC Interrupt Enable register */
#define REG_PMECC_IDR          REG_ACCESS(WoReg, 0xFFFFE020U) /**< \brief (PMECC) PMECC Interrupt Disable Register */
#define REG_PMECC_IMR          REG_ACCESS(RoReg, 0xFFFFE024U) /**< \brief (PMECC) PMECC Interrupt Mask Register */
#define REG_PMECC_ISR          REG_ACCESS(RoReg, 0xFFFFE028U) /**< \brief (PMECC) PMECC Interrupt Status Register */
#define REG_PMECC_ECC0_0       REG_ACCESS(RoReg, 0xFFFFE040U) /**< \brief (PMECC) PMECC ECC 0 Register (sec_num = 0) */
#define REG_PMECC_ECC1_0       REG_ACCESS(RoReg, 0xFFFFE044U) /**< \brief (PMECC) PMECC ECC 1 Register (sec_num = 0) */
#define REG_PMECC_ECC2_0       REG_ACCESS(RoReg, 0xFFFFE048U) /**< \brief (PMECC) PMECC ECC 2 Register (sec_num = 0) */
#define REG_PMECC_ECC3_0       REG_ACCESS(RoReg, 0xFFFFE04CU) /**< \brief (PMECC) PMECC ECC 3 Register (sec_num = 0) */
#define REG_PMECC_ECC4_0       REG_ACCESS(RoReg, 0xFFFFE050U) /**< \brief (PMECC) PMECC ECC 4 Register (sec_num = 0) */
#define REG_PMECC_ECC5_0       REG_ACCESS(RoReg, 0xFFFFE054U) /**< \brief (PMECC) PMECC ECC 5 Register (sec_num = 0) */
#define REG_PMECC_ECC6_0       REG_ACCESS(RoReg, 0xFFFFE058U) /**< \brief (PMECC) PMECC ECC 6 Register (sec_num = 0) */
#define REG_PMECC_ECC7_0       REG_ACCESS(RoReg, 0xFFFFE05CU) /**< \brief (PMECC) PMECC ECC 7 Register (sec_num = 0) */
#define REG_PMECC_ECC8_0       REG_ACCESS(RoReg, 0xFFFFE060U) /**< \brief (PMECC) PMECC ECC 8 Register (sec_num = 0) */
#define REG_PMECC_ECC9_0       REG_ACCESS(RoReg, 0xFFFFE064U) /**< \brief (PMECC) PMECC ECC 9 Register (sec_num = 0) */
#define REG_PMECC_ECC10_0      REG_ACCESS(RoReg, 0xFFFFE068U) /**< \brief (PMECC) PMECC ECC 10 Register (sec_num = 0) */
#define REG_PMECC_ECC0_1       REG_ACCESS(RoReg, 0xFFFFE080U) /**< \brief (PMECC) PMECC ECC 0 Register (sec_num = 1) */
#define REG_PMECC_ECC1_1       REG_ACCESS(RoReg, 0xFFFFE084U) /**< \brief (PMECC) PMECC ECC 1 Register (sec_num = 1) */
#define REG_PMECC_ECC2_1       REG_ACCESS(RoReg, 0xFFFFE088U) /**< \brief (PMECC) PMECC ECC 2 Register (sec_num = 1) */
#define REG_PMECC_ECC3_1       REG_ACCESS(RoReg, 0xFFFFE08CU) /**< \brief (PMECC) PMECC ECC 3 Register (sec_num = 1) */
#define REG_PMECC_ECC4_1       REG_ACCESS(RoReg, 0xFFFFE090U) /**< \brief (PMECC) PMECC ECC 4 Register (sec_num = 1) */
#define REG_PMECC_ECC5_1       REG_ACCESS(RoReg, 0xFFFFE094U) /**< \brief (PMECC) PMECC ECC 5 Register (sec_num = 1) */
#define REG_PMECC_ECC6_1       REG_ACCESS(RoReg, 0xFFFFE098U) /**< \brief (PMECC) PMECC ECC 6 Register (sec_num = 1) */
#define REG_PMECC_ECC7_1       REG_ACCESS(RoReg, 0xFFFFE09CU) /**< \brief (PMECC) PMECC ECC 7 Register (sec_num = 1) */
#define REG_PMECC_ECC8_1       REG_ACCESS(RoReg, 0xFFFFE0A0U) /**< \brief (PMECC) PMECC ECC 8 Register (sec_num = 1) */
#define REG_PMECC_ECC9_1       REG_ACCESS(RoReg, 0xFFFFE0A4U) /**< \brief (PMECC) PMECC ECC 9 Register (sec_num = 1) */
#define REG_PMECC_ECC10_1      REG_ACCESS(RoReg, 0xFFFFE0A8U) /**< \brief (PMECC) PMECC ECC 10 Register (sec_num = 1) */
#define REG_PMECC_ECC0_2       REG_ACCESS(RoReg, 0xFFFFE0C0U) /**< \brief (PMECC) PMECC ECC 0 Register (sec_num = 2) */
#define REG_PMECC_ECC1_2       REG_ACCESS(RoReg, 0xFFFFE0C4U) /**< \brief (PMECC) PMECC ECC 1 Register (sec_num = 2) */
#define REG_PMECC_ECC2_2       REG_ACCESS(RoReg, 0xFFFFE0C8U) /**< \brief (PMECC) PMECC ECC 2 Register (sec_num = 2) */
#define REG_PMECC_ECC3_2       REG_ACCESS(RoReg, 0xFFFFE0CCU) /**< \brief (PMECC) PMECC ECC 3 Register (sec_num = 2) */
#define REG_PMECC_ECC4_2       REG_ACCESS(RoReg, 0xFFFFE0D0U) /**< \brief (PMECC) PMECC ECC 4 Register (sec_num = 2) */
#define REG_PMECC_ECC5_2       REG_ACCESS(RoReg, 0xFFFFE0D4U) /**< \brief (PMECC) PMECC ECC 5 Register (sec_num = 2) */
#define REG_PMECC_ECC6_2       REG_ACCESS(RoReg, 0xFFFFE0D8U) /**< \brief (PMECC) PMECC ECC 6 Register (sec_num = 2) */
#define REG_PMECC_ECC7_2       REG_ACCESS(RoReg, 0xFFFFE0DCU) /**< \brief (PMECC) PMECC ECC 7 Register (sec_num = 2) */
#define REG_PMECC_ECC8_2       REG_ACCESS(RoReg, 0xFFFFE0E0U) /**< \brief (PMECC) PMECC ECC 8 Register (sec_num = 2) */
#define REG_PMECC_ECC9_2       REG_ACCESS(RoReg, 0xFFFFE0E4U) /**< \brief (PMECC) PMECC ECC 9 Register (sec_num = 2) */
#define REG_PMECC_ECC10_2      REG_ACCESS(RoReg, 0xFFFFE0E8U) /**< \brief (PMECC) PMECC ECC 10 Register (sec_num = 2) */
#define REG_PMECC_ECC0_3       REG_ACCESS(RoReg, 0xFFFFE100U) /**< \brief (PMECC) PMECC ECC 0 Register (sec_num = 3) */
#define REG_PMECC_ECC1_3       REG_ACCESS(RoReg, 0xFFFFE104U) /**< \brief (PMECC) PMECC ECC 1 Register (sec_num = 3) */
#define REG_PMECC_ECC2_3       REG_ACCESS(RoReg, 0xFFFFE108U) /**< \brief (PMECC) PMECC ECC 2 Register (sec_num = 3) */
#define REG_PMECC_ECC3_3       REG_ACCESS(RoReg, 0xFFFFE10CU) /**< \brief (PMECC) PMECC ECC 3 Register (sec_num = 3) */
#define REG_PMECC_ECC4_3       REG_ACCESS(RoReg, 0xFFFFE110U) /**< \brief (PMECC) PMECC ECC 4 Register (sec_num = 3) */
#define REG_PMECC_ECC5_3       REG_ACCESS(RoReg, 0xFFFFE114U) /**< \brief (PMECC) PMECC ECC 5 Register (sec_num = 3) */
#define REG_PMECC_ECC6_3       REG_ACCESS(RoReg, 0xFFFFE118U) /**< \brief (PMECC) PMECC ECC 6 Register (sec_num = 3) */
#define REG_PMECC_ECC7_3       REG_ACCESS(RoReg, 0xFFFFE11CU) /**< \brief (PMECC) PMECC ECC 7 Register (sec_num = 3) */
#define REG_PMECC_ECC8_3       REG_ACCESS(RoReg, 0xFFFFE120U) /**< \brief (PMECC) PMECC ECC 8 Register (sec_num = 3) */
#define REG_PMECC_ECC9_3       REG_ACCESS(RoReg, 0xFFFFE124U) /**< \brief (PMECC) PMECC ECC 9 Register (sec_num = 3) */
#define REG_PMECC_ECC10_3      REG_ACCESS(RoReg, 0xFFFFE128U) /**< \brief (PMECC) PMECC ECC 10 Register (sec_num = 3) */
#define REG_PMECC_ECC0_4       REG_ACCESS(RoReg, 0xFFFFE140U) /**< \brief (PMECC) PMECC ECC 0 Register (sec_num = 4) */
#define REG_PMECC_ECC1_4       REG_ACCESS(RoReg, 0xFFFFE144U) /**< \brief (PMECC) PMECC ECC 1 Register (sec_num = 4) */
#define REG_PMECC_ECC2_4       REG_ACCESS(RoReg, 0xFFFFE148U) /**< \brief (PMECC) PMECC ECC 2 Register (sec_num = 4) */
#define REG_PMECC_ECC3_4       REG_ACCESS(RoReg, 0xFFFFE14CU) /**< \brief (PMECC) PMECC ECC 3 Register (sec_num = 4) */
#define REG_PMECC_ECC4_4       REG_ACCESS(RoReg, 0xFFFFE150U) /**< \brief (PMECC) PMECC ECC 4 Register (sec_num = 4) */
#define REG_PMECC_ECC5_4       REG_ACCESS(RoReg, 0xFFFFE154U) /**< \brief (PMECC) PMECC ECC 5 Register (sec_num = 4) */
#define REG_PMECC_ECC6_4       REG_ACCESS(RoReg, 0xFFFFE158U) /**< \brief (PMECC) PMECC ECC 6 Register (sec_num = 4) */
#define REG_PMECC_ECC7_4       REG_ACCESS(RoReg, 0xFFFFE15CU) /**< \brief (PMECC) PMECC ECC 7 Register (sec_num = 4) */
#define REG_PMECC_ECC8_4       REG_ACCESS(RoReg, 0xFFFFE160U) /**< \brief (PMECC) PMECC ECC 8 Register (sec_num = 4) */
#define REG_PMECC_ECC9_4       REG_ACCESS(RoReg, 0xFFFFE164U) /**< \brief (PMECC) PMECC ECC 9 Register (sec_num = 4) */
#define REG_PMECC_ECC10_4      REG_ACCESS(RoReg, 0xFFFFE168U) /**< \brief (PMECC) PMECC ECC 10 Register (sec_num = 4) */
#define REG_PMECC_ECC0_5       REG_ACCESS(RoReg, 0xFFFFE180U) /**< \brief (PMECC) PMECC ECC 0 Register (sec_num = 5) */
#define REG_PMECC_ECC1_5       REG_ACCESS(RoReg, 0xFFFFE184U) /**< \brief (PMECC) PMECC ECC 1 Register (sec_num = 5) */
#define REG_PMECC_ECC2_5       REG_ACCESS(RoReg, 0xFFFFE188U) /**< \brief (PMECC) PMECC ECC 2 Register (sec_num = 5) */
#define REG_PMECC_ECC3_5       REG_ACCESS(RoReg, 0xFFFFE18CU) /**< \brief (PMECC) PMECC ECC 3 Register (sec_num = 5) */
#define REG_PMECC_ECC4_5       REG_ACCESS(RoReg, 0xFFFFE190U) /**< \brief (PMECC) PMECC ECC 4 Register (sec_num = 5) */
#define REG_PMECC_ECC5_5       REG_ACCESS(RoReg, 0xFFFFE194U) /**< \brief (PMECC) PMECC ECC 5 Register (sec_num = 5) */
#define REG_PMECC_ECC6_5       REG_ACCESS(RoReg, 0xFFFFE198U) /**< \brief (PMECC) PMECC ECC 6 Register (sec_num = 5) */
#define REG_PMECC_ECC7_5       REG_ACCESS(RoReg, 0xFFFFE19CU) /**< \brief (PMECC) PMECC ECC 7 Register (sec_num = 5) */
#define REG_PMECC_ECC8_5       REG_ACCESS(RoReg, 0xFFFFE1A0U) /**< \brief (PMECC) PMECC ECC 8 Register (sec_num = 5) */
#define REG_PMECC_ECC9_5       REG_ACCESS(RoReg, 0xFFFFE1A4U) /**< \brief (PMECC) PMECC ECC 9 Register (sec_num = 5) */
#define REG_PMECC_ECC10_5      REG_ACCESS(RoReg, 0xFFFFE1A8U) /**< \brief (PMECC) PMECC ECC 10 Register (sec_num = 5) */
#define REG_PMECC_ECC0_6       REG_ACCESS(RoReg, 0xFFFFE1C0U) /**< \brief (PMECC) PMECC ECC 0 Register (sec_num = 6) */
#define REG_PMECC_ECC1_6       REG_ACCESS(RoReg, 0xFFFFE1C4U) /**< \brief (PMECC) PMECC ECC 1 Register (sec_num = 6) */
#define REG_PMECC_ECC2_6       REG_ACCESS(RoReg, 0xFFFFE1C8U) /**< \brief (PMECC) PMECC ECC 2 Register (sec_num = 6) */
#define REG_PMECC_ECC3_6       REG_ACCESS(RoReg, 0xFFFFE1CCU) /**< \brief (PMECC) PMECC ECC 3 Register (sec_num = 6) */
#define REG_PMECC_ECC4_6       REG_ACCESS(RoReg, 0xFFFFE1D0U) /**< \brief (PMECC) PMECC ECC 4 Register (sec_num = 6) */
#define REG_PMECC_ECC5_6       REG_ACCESS(RoReg, 0xFFFFE1D4U) /**< \brief (PMECC) PMECC ECC 5 Register (sec_num = 6) */
#define REG_PMECC_ECC6_6       REG_ACCESS(RoReg, 0xFFFFE1D8U) /**< \brief (PMECC) PMECC ECC 6 Register (sec_num = 6) */
#define REG_PMECC_ECC7_6       REG_ACCESS(RoReg, 0xFFFFE1DCU) /**< \brief (PMECC) PMECC ECC 7 Register (sec_num = 6) */
#define REG_PMECC_ECC8_6       REG_ACCESS(RoReg, 0xFFFFE1E0U) /**< \brief (PMECC) PMECC ECC 8 Register (sec_num = 6) */
#define REG_PMECC_ECC9_6       REG_ACCESS(RoReg, 0xFFFFE1E4U) /**< \brief (PMECC) PMECC ECC 9 Register (sec_num = 6) */
#define REG_PMECC_ECC10_6      REG_ACCESS(RoReg, 0xFFFFE1E8U) /**< \brief (PMECC) PMECC ECC 10 Register (sec_num = 6) */
#define REG_PMECC_ECC0_7       REG_ACCESS(RoReg, 0xFFFFE200U) /**< \brief (PMECC) PMECC ECC 0 Register (sec_num = 7) */
#define REG_PMECC_ECC1_7       REG_ACCESS(RoReg, 0xFFFFE204U) /**< \brief (PMECC) PMECC ECC 1 Register (sec_num = 7) */
#define REG_PMECC_ECC2_7       REG_ACCESS(RoReg, 0xFFFFE208U) /**< \brief (PMECC) PMECC ECC 2 Register (sec_num = 7) */
#define REG_PMECC_ECC3_7       REG_ACCESS(RoReg, 0xFFFFE20CU) /**< \brief (PMECC) PMECC ECC 3 Register (sec_num = 7) */
#define REG_PMECC_ECC4_7       REG_ACCESS(RoReg, 0xFFFFE210U) /**< \brief (PMECC) PMECC ECC 4 Register (sec_num = 7) */
#define REG_PMECC_ECC5_7       REG_ACCESS(RoReg, 0xFFFFE214U) /**< \brief (PMECC) PMECC ECC 5 Register (sec_num = 7) */
#define REG_PMECC_ECC6_7       REG_ACCESS(RoReg, 0xFFFFE218U) /**< \brief (PMECC) PMECC ECC 6 Register (sec_num = 7) */
#define REG_PMECC_ECC7_7       REG_ACCESS(RoReg, 0xFFFFE21CU) /**< \brief (PMECC) PMECC ECC 7 Register (sec_num = 7) */
#define REG_PMECC_ECC8_7       REG_ACCESS(RoReg, 0xFFFFE220U) /**< \brief (PMECC) PMECC ECC 8 Register (sec_num = 7) */
#define REG_PMECC_ECC9_7       REG_ACCESS(RoReg, 0xFFFFE224U) /**< \brief (PMECC) PMECC ECC 9 Register (sec_num = 7) */
#define REG_PMECC_ECC10_7      REG_ACCESS(RoReg, 0xFFFFE228U) /**< \brief (PMECC) PMECC ECC 10 Register (sec_num = 7) */
#define REG_PMECC_REM0_0       REG_ACCESS(RoReg, 0xFFFFE240U) /**< \brief (PMECC) PMECC REM 0 Register (sec_num = 0) */
#define REG_PMECC_REM1_0       REG_ACCESS(RoReg, 0xFFFFE244U) /**< \brief (PMECC) PMECC REM 1 Register (sec_num = 0) */
#define REG_PMECC_REM2_0       REG_ACCESS(RoReg, 0xFFFFE248U) /**< \brief (PMECC) PMECC REM 2 Register (sec_num = 0) */
#define REG_PMECC_REM3_0       REG_ACCESS(RoReg, 0xFFFFE24CU) /**< \brief (PMECC) PMECC REM 3 Register (sec_num = 0) */
#define REG_PMECC_REM4_0       REG_ACCESS(RoReg, 0xFFFFE250U) /**< \brief (PMECC) PMECC REM 4 Register (sec_num = 0) */
#define REG_PMECC_REM5_0       REG_ACCESS(RoReg, 0xFFFFE254U) /**< \brief (PMECC) PMECC REM 5 Register (sec_num = 0) */
#define REG_PMECC_REM6_0       REG_ACCESS(RoReg, 0xFFFFE258U) /**< \brief (PMECC) PMECC REM 6 Register (sec_num = 0) */
#define REG_PMECC_REM7_0       REG_ACCESS(RoReg, 0xFFFFE25CU) /**< \brief (PMECC) PMECC REM 7 Register (sec_num = 0) */
#define REG_PMECC_REM8_0       REG_ACCESS(RoReg, 0xFFFFE260U) /**< \brief (PMECC) PMECC REM 8 Register (sec_num = 0) */
#define REG_PMECC_REM9_0       REG_ACCESS(RoReg, 0xFFFFE264U) /**< \brief (PMECC) PMECC REM 9 Register (sec_num = 0) */
#define REG_PMECC_REM10_0      REG_ACCESS(RoReg, 0xFFFFE268U) /**< \brief (PMECC) PMECC REM 10 Register (sec_num = 0) */
#define REG_PMECC_REM11_0      REG_ACCESS(RoReg, 0xFFFFE26CU) /**< \brief (PMECC) PMECC REM 11 Register (sec_num = 0) */
#define REG_PMECC_REM0_1       REG_ACCESS(RoReg, 0xFFFFE280U) /**< \brief (PMECC) PMECC REM 0 Register (sec_num = 1) */
#define REG_PMECC_REM1_1       REG_ACCESS(RoReg, 0xFFFFE284U) /**< \brief (PMECC) PMECC REM 1 Register (sec_num = 1) */
#define REG_PMECC_REM2_1       REG_ACCESS(RoReg, 0xFFFFE288U) /**< \brief (PMECC) PMECC REM 2 Register (sec_num = 1) */
#define REG_PMECC_REM3_1       REG_ACCESS(RoReg, 0xFFFFE28CU) /**< \brief (PMECC) PMECC REM 3 Register (sec_num = 1) */
#define REG_PMECC_REM4_1       REG_ACCESS(RoReg, 0xFFFFE290U) /**< \brief (PMECC) PMECC REM 4 Register (sec_num = 1) */
#define REG_PMECC_REM5_1       REG_ACCESS(RoReg, 0xFFFFE294U) /**< \brief (PMECC) PMECC REM 5 Register (sec_num = 1) */
#define REG_PMECC_REM6_1       REG_ACCESS(RoReg, 0xFFFFE298U) /**< \brief (PMECC) PMECC REM 6 Register (sec_num = 1) */
#define REG_PMECC_REM7_1       REG_ACCESS(RoReg, 0xFFFFE29CU) /**< \brief (PMECC) PMECC REM 7 Register (sec_num = 1) */
#define REG_PMECC_REM8_1       REG_ACCESS(RoReg, 0xFFFFE2A0U) /**< \brief (PMECC) PMECC REM 8 Register (sec_num = 1) */
#define REG_PMECC_REM9_1       REG_ACCESS(RoReg, 0xFFFFE2A4U) /**< \brief (PMECC) PMECC REM 9 Register (sec_num = 1) */
#define REG_PMECC_REM10_1      REG_ACCESS(RoReg, 0xFFFFE2A8U) /**< \brief (PMECC) PMECC REM 10 Register (sec_num = 1) */
#define REG_PMECC_REM11_1      REG_ACCESS(RoReg, 0xFFFFE2ACU) /**< \brief (PMECC) PMECC REM 11 Register (sec_num = 1) */
#define REG_PMECC_REM0_2       REG_ACCESS(RoReg, 0xFFFFE2C0U) /**< \brief (PMECC) PMECC REM 0 Register (sec_num = 2) */
#define REG_PMECC_REM1_2       REG_ACCESS(RoReg, 0xFFFFE2C4U) /**< \brief (PMECC) PMECC REM 1 Register (sec_num = 2) */
#define REG_PMECC_REM2_2       REG_ACCESS(RoReg, 0xFFFFE2C8U) /**< \brief (PMECC) PMECC REM 2 Register (sec_num = 2) */
#define REG_PMECC_REM3_2       REG_ACCESS(RoReg, 0xFFFFE2CCU) /**< \brief (PMECC) PMECC REM 3 Register (sec_num = 2) */
#define REG_PMECC_REM4_2       REG_ACCESS(RoReg, 0xFFFFE2D0U) /**< \brief (PMECC) PMECC REM 4 Register (sec_num = 2) */
#define REG_PMECC_REM5_2       REG_ACCESS(RoReg, 0xFFFFE2D4U) /**< \brief (PMECC) PMECC REM 5 Register (sec_num = 2) */
#define REG_PMECC_REM6_2       REG_ACCESS(RoReg, 0xFFFFE2D8U) /**< \brief (PMECC) PMECC REM 6 Register (sec_num = 2) */
#define REG_PMECC_REM7_2       REG_ACCESS(RoReg, 0xFFFFE2DCU) /**< \brief (PMECC) PMECC REM 7 Register (sec_num = 2) */
#define REG_PMECC_REM8_2       REG_ACCESS(RoReg, 0xFFFFE2E0U) /**< \brief (PMECC) PMECC REM 8 Register (sec_num = 2) */
#define REG_PMECC_REM9_2       REG_ACCESS(RoReg, 0xFFFFE2E4U) /**< \brief (PMECC) PMECC REM 9 Register (sec_num = 2) */
#define REG_PMECC_REM10_2      REG_ACCESS(RoReg, 0xFFFFE2E8U) /**< \brief (PMECC) PMECC REM 10 Register (sec_num = 2) */
#define REG_PMECC_REM11_2      REG_ACCESS(RoReg, 0xFFFFE2ECU) /**< \brief (PMECC) PMECC REM 11 Register (sec_num = 2) */
#define REG_PMECC_REM0_3       REG_ACCESS(RoReg, 0xFFFFE300U) /**< \brief (PMECC) PMECC REM 0 Register (sec_num = 3) */
#define REG_PMECC_REM1_3       REG_ACCESS(RoReg, 0xFFFFE304U) /**< \brief (PMECC) PMECC REM 1 Register (sec_num = 3) */
#define REG_PMECC_REM2_3       REG_ACCESS(RoReg, 0xFFFFE308U) /**< \brief (PMECC) PMECC REM 2 Register (sec_num = 3) */
#define REG_PMECC_REM3_3       REG_ACCESS(RoReg, 0xFFFFE30CU) /**< \brief (PMECC) PMECC REM 3 Register (sec_num = 3) */
#define REG_PMECC_REM4_3       REG_ACCESS(RoReg, 0xFFFFE310U) /**< \brief (PMECC) PMECC REM 4 Register (sec_num = 3) */
#define REG_PMECC_REM5_3       REG_ACCESS(RoReg, 0xFFFFE314U) /**< \brief (PMECC) PMECC REM 5 Register (sec_num = 3) */
#define REG_PMECC_REM6_3       REG_ACCESS(RoReg, 0xFFFFE318U) /**< \brief (PMECC) PMECC REM 6 Register (sec_num = 3) */
#define REG_PMECC_REM7_3       REG_ACCESS(RoReg, 0xFFFFE31CU) /**< \brief (PMECC) PMECC REM 7 Register (sec_num = 3) */
#define REG_PMECC_REM8_3       REG_ACCESS(RoReg, 0xFFFFE320U) /**< \brief (PMECC) PMECC REM 8 Register (sec_num = 3) */
#define REG_PMECC_REM9_3       REG_ACCESS(RoReg, 0xFFFFE324U) /**< \brief (PMECC) PMECC REM 9 Register (sec_num = 3) */
#define REG_PMECC_REM10_3      REG_ACCESS(RoReg, 0xFFFFE328U) /**< \brief (PMECC) PMECC REM 10 Register (sec_num = 3) */
#define REG_PMECC_REM11_3      REG_ACCESS(RoReg, 0xFFFFE32CU) /**< \brief (PMECC) PMECC REM 11 Register (sec_num = 3) */
#define REG_PMECC_REM0_4       REG_ACCESS(RoReg, 0xFFFFE340U) /**< \brief (PMECC) PMECC REM 0 Register (sec_num = 4) */
#define REG_PMECC_REM1_4       REG_ACCESS(RoReg, 0xFFFFE344U) /**< \brief (PMECC) PMECC REM 1 Register (sec_num = 4) */
#define REG_PMECC_REM2_4       REG_ACCESS(RoReg, 0xFFFFE348U) /**< \brief (PMECC) PMECC REM 2 Register (sec_num = 4) */
#define REG_PMECC_REM3_4       REG_ACCESS(RoReg, 0xFFFFE34CU) /**< \brief (PMECC) PMECC REM 3 Register (sec_num = 4) */
#define REG_PMECC_REM4_4       REG_ACCESS(RoReg, 0xFFFFE350U) /**< \brief (PMECC) PMECC REM 4 Register (sec_num = 4) */
#define REG_PMECC_REM5_4       REG_ACCESS(RoReg, 0xFFFFE354U) /**< \brief (PMECC) PMECC REM 5 Register (sec_num = 4) */
#define REG_PMECC_REM6_4       REG_ACCESS(RoReg, 0xFFFFE358U) /**< \brief (PMECC) PMECC REM 6 Register (sec_num = 4) */
#define REG_PMECC_REM7_4       REG_ACCESS(RoReg, 0xFFFFE35CU) /**< \brief (PMECC) PMECC REM 7 Register (sec_num = 4) */
#define REG_PMECC_REM8_4       REG_ACCESS(RoReg, 0xFFFFE360U) /**< \brief (PMECC) PMECC REM 8 Register (sec_num = 4) */
#define REG_PMECC_REM9_4       REG_ACCESS(RoReg, 0xFFFFE364U) /**< \brief (PMECC) PMECC REM 9 Register (sec_num = 4) */
#define REG_PMECC_REM10_4      REG_ACCESS(RoReg, 0xFFFFE368U) /**< \brief (PMECC) PMECC REM 10 Register (sec_num = 4) */
#define REG_PMECC_REM11_4      REG_ACCESS(RoReg, 0xFFFFE36CU) /**< \brief (PMECC) PMECC REM 11 Register (sec_num = 4) */
#define REG_PMECC_REM0_5       REG_ACCESS(RoReg, 0xFFFFE380U) /**< \brief (PMECC) PMECC REM 0 Register (sec_num = 5) */
#define REG_PMECC_REM1_5       REG_ACCESS(RoReg, 0xFFFFE384U) /**< \brief (PMECC) PMECC REM 1 Register (sec_num = 5) */
#define REG_PMECC_REM2_5       REG_ACCESS(RoReg, 0xFFFFE388U) /**< \brief (PMECC) PMECC REM 2 Register (sec_num = 5) */
#define REG_PMECC_REM3_5       REG_ACCESS(RoReg, 0xFFFFE38CU) /**< \brief (PMECC) PMECC REM 3 Register (sec_num = 5) */
#define REG_PMECC_REM4_5       REG_ACCESS(RoReg, 0xFFFFE390U) /**< \brief (PMECC) PMECC REM 4 Register (sec_num = 5) */
#define REG_PMECC_REM5_5       REG_ACCESS(RoReg, 0xFFFFE394U) /**< \brief (PMECC) PMECC REM 5 Register (sec_num = 5) */
#define REG_PMECC_REM6_5       REG_ACCESS(RoReg, 0xFFFFE398U) /**< \brief (PMECC) PMECC REM 6 Register (sec_num = 5) */
#define REG_PMECC_REM7_5       REG_ACCESS(RoReg, 0xFFFFE39CU) /**< \brief (PMECC) PMECC REM 7 Register (sec_num = 5) */
#define REG_PMECC_REM8_5       REG_ACCESS(RoReg, 0xFFFFE3A0U) /**< \brief (PMECC) PMECC REM 8 Register (sec_num = 5) */
#define REG_PMECC_REM9_5       REG_ACCESS(RoReg, 0xFFFFE3A4U) /**< \brief (PMECC) PMECC REM 9 Register (sec_num = 5) */
#define REG_PMECC_REM10_5      REG_ACCESS(RoReg, 0xFFFFE3A8U) /**< \brief (PMECC) PMECC REM 10 Register (sec_num = 5) */
#define REG_PMECC_REM11_5      REG_ACCESS(RoReg, 0xFFFFE3ACU) /**< \brief (PMECC) PMECC REM 11 Register (sec_num = 5) */
#define REG_PMECC_REM0_6       REG_ACCESS(RoReg, 0xFFFFE3C0U) /**< \brief (PMECC) PMECC REM 0 Register (sec_num = 6) */
#define REG_PMECC_REM1_6       REG_ACCESS(RoReg, 0xFFFFE3C4U) /**< \brief (PMECC) PMECC REM 1 Register (sec_num = 6) */
#define REG_PMECC_REM2_6       REG_ACCESS(RoReg, 0xFFFFE3C8U) /**< \brief (PMECC) PMECC REM 2 Register (sec_num = 6) */
#define REG_PMECC_REM3_6       REG_ACCESS(RoReg, 0xFFFFE3CCU) /**< \brief (PMECC) PMECC REM 3 Register (sec_num = 6) */
#define REG_PMECC_REM4_6       REG_ACCESS(RoReg, 0xFFFFE3D0U) /**< \brief (PMECC) PMECC REM 4 Register (sec_num = 6) */
#define REG_PMECC_REM5_6       REG_ACCESS(RoReg, 0xFFFFE3D4U) /**< \brief (PMECC) PMECC REM 5 Register (sec_num = 6) */
#define REG_PMECC_REM6_6       REG_ACCESS(RoReg, 0xFFFFE3D8U) /**< \brief (PMECC) PMECC REM 6 Register (sec_num = 6) */
#define REG_PMECC_REM7_6       REG_ACCESS(RoReg, 0xFFFFE3DCU) /**< \brief (PMECC) PMECC REM 7 Register (sec_num = 6) */
#define REG_PMECC_REM8_6       REG_ACCESS(RoReg, 0xFFFFE3E0U) /**< \brief (PMECC) PMECC REM 8 Register (sec_num = 6) */
#define REG_PMECC_REM9_6       REG_ACCESS(RoReg, 0xFFFFE3E4U) /**< \brief (PMECC) PMECC REM 9 Register (sec_num = 6) */
#define REG_PMECC_REM10_6      REG_ACCESS(RoReg, 0xFFFFE3E8U) /**< \brief (PMECC) PMECC REM 10 Register (sec_num = 6) */
#define REG_PMECC_REM11_6      REG_ACCESS(RoReg, 0xFFFFE3ECU) /**< \brief (PMECC) PMECC REM 11 Register (sec_num = 6) */
#define REG_PMECC_REM0_7       REG_ACCESS(RoReg, 0xFFFFE400U) /**< \brief (PMECC) PMECC REM 0 Register (sec_num = 7) */
#define REG_PMECC_REM1_7       REG_ACCESS(RoReg, 0xFFFFE404U) /**< \brief (PMECC) PMECC REM 1 Register (sec_num = 7) */
#define REG_PMECC_REM2_7       REG_ACCESS(RoReg, 0xFFFFE408U) /**< \brief (PMECC) PMECC REM 2 Register (sec_num = 7) */
#define REG_PMECC_REM3_7       REG_ACCESS(RoReg, 0xFFFFE40CU) /**< \brief (PMECC) PMECC REM 3 Register (sec_num = 7) */
#define REG_PMECC_REM4_7       REG_ACCESS(RoReg, 0xFFFFE410U) /**< \brief (PMECC) PMECC REM 4 Register (sec_num = 7) */
#define REG_PMECC_REM5_7       REG_ACCESS(RoReg, 0xFFFFE414U) /**< \brief (PMECC) PMECC REM 5 Register (sec_num = 7) */
#define REG_PMECC_REM6_7       REG_ACCESS(RoReg, 0xFFFFE418U) /**< \brief (PMECC) PMECC REM 6 Register (sec_num = 7) */
#define REG_PMECC_REM7_7       REG_ACCESS(RoReg, 0xFFFFE41CU) /**< \brief (PMECC) PMECC REM 7 Register (sec_num = 7) */
#define REG_PMECC_REM8_7       REG_ACCESS(RoReg, 0xFFFFE420U) /**< \brief (PMECC) PMECC REM 8 Register (sec_num = 7) */
#define REG_PMECC_REM9_7       REG_ACCESS(RoReg, 0xFFFFE424U) /**< \brief (PMECC) PMECC REM 9 Register (sec_num = 7) */
#define REG_PMECC_REM10_7      REG_ACCESS(RoReg, 0xFFFFE428U) /**< \brief (PMECC) PMECC REM 10 Register (sec_num = 7) */
#define REG_PMECC_REM11_7      REG_ACCESS(RoReg, 0xFFFFE42CU) /**< \brief (PMECC) PMECC REM 11 Register (sec_num = 7) */
/* ========== Register definition for PMERRLOC peripheral ========== */
#define REG_PMERRLOC_ELCFG     REG_ACCESS(RwReg, 0xFFFFE600U) /**< \brief (PMERRLOC) Error Location Configuration Register */
#define REG_PMERRLOC_ELPRIM    REG_ACCESS(RoReg, 0xFFFFE604U) /**< \brief (PMERRLOC) Error Location Primitive Register */
#define REG_PMERRLOC_ELEN      REG_ACCESS(RwReg, 0xFFFFE608U) /**< \brief (PMERRLOC) Error Location Enable Register */
#define REG_PMERRLOC_ELDIS     REG_ACCESS(RwReg, 0xFFFFE60CU) /**< \brief (PMERRLOC) Error Location Disable Register */
#define REG_PMERRLOC_ELSR      REG_ACCESS(RwReg, 0xFFFFE610U) /**< \brief (PMERRLOC) Error Location Status Register */
#define REG_PMERRLOC_ELIER     REG_ACCESS(RoReg, 0xFFFFE614U) /**< \brief (PMERRLOC) Error Location Interrupt Enable register */
#define REG_PMERRLOC_ELIDR     REG_ACCESS(RoReg, 0xFFFFE618U) /**< \brief (PMERRLOC) Error Location Interrupt Disable Register */
#define REG_PMERRLOC_ELIMR     REG_ACCESS(RoReg, 0xFFFFE61CU) /**< \brief (PMERRLOC) Error Location Interrupt Mask Register */
#define REG_PMERRLOC_ELISR     REG_ACCESS(RoReg, 0xFFFFE620U) /**< \brief (PMERRLOC) Error Location Interrupt Status Register */
#define REG_PMERRLOC_SIGMA     REG_ACCESS(RwReg, 0xFFFFE628U) /**< \brief (PMERRLOC) PMECC SIGMA 0 Register */
#define REG_PMERRLOC_EL        REG_ACCESS(RoReg, 0xFFFFE68CU) /**< \brief (PMERRLOC) PMECC Error Location 0 Register */
/* ========== Register definition for DDRSDRC peripheral ========== */
#define REG_DDRSDRC_MR         REG_ACCESS(RwReg, 0xFFFFE800U) /**< \brief (DDRSDRC) DDRSDRC Mode Register */
#define REG_DDRSDRC_RTR        REG_ACCESS(RwReg, 0xFFFFE804U) /**< \brief (DDRSDRC) DDRSDRC Refresh Timer Register */
#define REG_DDRSDRC_CR         REG_ACCESS(RwReg, 0xFFFFE808U) /**< \brief (DDRSDRC) DDRSDRC Configuration Register */
#define REG_DDRSDRC_TPR0       REG_ACCESS(RwReg, 0xFFFFE80CU) /**< \brief (DDRSDRC) DDRSDRC Timing Parameter 0 Register */
#define REG_DDRSDRC_TPR1       REG_ACCESS(RwReg, 0xFFFFE810U) /**< \brief (DDRSDRC) DDRSDRC Timing Parameter 1 Register */
#define REG_DDRSDRC_TPR2       REG_ACCESS(RwReg, 0xFFFFE814U) /**< \brief (DDRSDRC) DDRSDRC Timing Parameter 2 Register */
#define REG_DDRSDRC_LPR        REG_ACCESS(RwReg, 0xFFFFE81CU) /**< \brief (DDRSDRC) DDRSDRC Low-power Register */
#define REG_DDRSDRC_MD         REG_ACCESS(RwReg, 0xFFFFE820U) /**< \brief (DDRSDRC) DDRSDRC Memory Device Register */
#define REG_DDRSDRC_DLL        REG_ACCESS(RoReg, 0xFFFFE824U) /**< \brief (DDRSDRC) DDRSDRC DLL Information Register */
#define REG_DDRSDRC_HS         REG_ACCESS(RwReg, 0xFFFFE82CU) /**< \brief (DDRSDRC) DDRSDRC High Speed Register */
#define REG_DDRSDRC_WPMR       REG_ACCESS(RwReg, 0xFFFFE8E4U) /**< \brief (DDRSDRC) DDRSDRC Write Protect Mode Register */
#define REG_DDRSDRC_WPSR       REG_ACCESS(RoReg, 0xFFFFE8E8U) /**< \brief (DDRSDRC) DDRSDRC Write Protect Status Register */
/* ========== Register definition for SMC peripheral ========== */
#define REG_SMC_SETUP0         REG_ACCESS(RwReg, 0xFFFFEA00U) /**< \brief (SMC) SMC Setup Register (CS_number = 0) */
#define REG_SMC_PULSE0         REG_ACCESS(RwReg, 0xFFFFEA04U) /**< \brief (SMC) SMC Pulse Register (CS_number = 0) */
#define REG_SMC_CYCLE0         REG_ACCESS(RwReg, 0xFFFFEA08U) /**< \brief (SMC) SMC Cycle Register (CS_number = 0) */
#define REG_SMC_MODE0          REG_ACCESS(RwReg, 0xFFFFEA0CU) /**< \brief (SMC) SMC Mode Register (CS_number = 0) */
#define REG_SMC_SETUP1         REG_ACCESS(RwReg, 0xFFFFEA10U) /**< \brief (SMC) SMC Setup Register (CS_number = 1) */
#define REG_SMC_PULSE1         REG_ACCESS(RwReg, 0xFFFFEA14U) /**< \brief (SMC) SMC Pulse Register (CS_number = 1) */
#define REG_SMC_CYCLE1         REG_ACCESS(RwReg, 0xFFFFEA18U) /**< \brief (SMC) SMC Cycle Register (CS_number = 1) */
#define REG_SMC_MODE1          REG_ACCESS(RwReg, 0xFFFFEA1CU) /**< \brief (SMC) SMC Mode Register (CS_number = 1) */
#define REG_SMC_SETUP2         REG_ACCESS(RwReg, 0xFFFFEA20U) /**< \brief (SMC) SMC Setup Register (CS_number = 2) */
#define REG_SMC_PULSE2         REG_ACCESS(RwReg, 0xFFFFEA24U) /**< \brief (SMC) SMC Pulse Register (CS_number = 2) */
#define REG_SMC_CYCLE2         REG_ACCESS(RwReg, 0xFFFFEA28U) /**< \brief (SMC) SMC Cycle Register (CS_number = 2) */
#define REG_SMC_MODE2          REG_ACCESS(RwReg, 0xFFFFEA2CU) /**< \brief (SMC) SMC Mode Register (CS_number = 2) */
#define REG_SMC_SETUP3         REG_ACCESS(RwReg, 0xFFFFEA30U) /**< \brief (SMC) SMC Setup Register (CS_number = 3) */
#define REG_SMC_PULSE3         REG_ACCESS(RwReg, 0xFFFFEA34U) /**< \brief (SMC) SMC Pulse Register (CS_number = 3) */
#define REG_SMC_CYCLE3         REG_ACCESS(RwReg, 0xFFFFEA38U) /**< \brief (SMC) SMC Cycle Register (CS_number = 3) */
#define REG_SMC_MODE3          REG_ACCESS(RwReg, 0xFFFFEA3CU) /**< \brief (SMC) SMC Mode Register (CS_number = 3) */
#define REG_SMC_SETUP4         REG_ACCESS(RwReg, 0xFFFFEA40U) /**< \brief (SMC) SMC Setup Register (CS_number = 4) */
#define REG_SMC_PULSE4         REG_ACCESS(RwReg, 0xFFFFEA44U) /**< \brief (SMC) SMC Pulse Register (CS_number = 4) */
#define REG_SMC_CYCLE4         REG_ACCESS(RwReg, 0xFFFFEA48U) /**< \brief (SMC) SMC Cycle Register (CS_number = 4) */
#define REG_SMC_MODE4          REG_ACCESS(RwReg, 0xFFFFEA4CU) /**< \brief (SMC) SMC Mode Register (CS_number = 4) */
#define REG_SMC_SETUP5         REG_ACCESS(RwReg, 0xFFFFEA50U) /**< \brief (SMC) SMC Setup Register (CS_number = 5) */
#define REG_SMC_PULSE5         REG_ACCESS(RwReg, 0xFFFFEA54U) /**< \brief (SMC) SMC Pulse Register (CS_number = 5) */
#define REG_SMC_CYCLE5         REG_ACCESS(RwReg, 0xFFFFEA58U) /**< \brief (SMC) SMC Cycle Register (CS_number = 5) */
#define REG_SMC_MODE5          REG_ACCESS(RwReg, 0xFFFFEA5CU) /**< \brief (SMC) SMC Mode Register (CS_number = 5) */
#define REG_SMC_DELAY1         REG_ACCESS(RwReg, 0xFFFFEAC0U) /**< \brief (SMC) SMC Delay on I/O */
#define REG_SMC_DELAY2         REG_ACCESS(RwReg, 0xFFFFEAC4U) /**< \brief (SMC) SMC Delay on I/O */
#define REG_SMC_DELAY3         REG_ACCESS(RwReg, 0xFFFFEAC8U) /**< \brief (SMC) SMC Delay on I/O */
#define REG_SMC_DELAY4         REG_ACCESS(RwReg, 0xFFFFEACCU) /**< \brief (SMC) SMC Delay on I/O */
#define REG_SMC_DELAY5         REG_ACCESS(RwReg, 0xFFFFEAD0U) /**< \brief (SMC) SMC Delay on I/O */
#define REG_SMC_DELAY6         REG_ACCESS(RwReg, 0xFFFFEAD4U) /**< \brief (SMC) SMC Delay on I/O */
#define REG_SMC_DELAY7         REG_ACCESS(RwReg, 0xFFFFEAD8U) /**< \brief (SMC) SMC Delay on I/O */
#define REG_SMC_DELAY8         REG_ACCESS(RwReg, 0xFFFFEADCU) /**< \brief (SMC) SMC Delay on I/O */
#define REG_SMC_WPMR           REG_ACCESS(RwReg, 0xFFFFEAE4U) /**< \brief (SMC) SMC Write Protect Mode Register */
#define REG_SMC_WPSR           REG_ACCESS(RoReg, 0xFFFFEAE8U) /**< \brief (SMC) SMC Write Protect Status Register */
/* ========== Register definition for DMAC peripheral ========== */
#define REG_DMAC_GCFG          REG_ACCESS(RwReg, 0xFFFFEC00U) /**< \brief (DMAC) DMAC Global Configuration Register */
#define REG_DMAC_EN            REG_ACCESS(RwReg, 0xFFFFEC04U) /**< \brief (DMAC) DMAC Enable Register */
#define REG_DMAC_SREQ          REG_ACCESS(RwReg, 0xFFFFEC08U) /**< \brief (DMAC) DMAC Software Single Request Register */
#define REG_DMAC_CREQ          REG_ACCESS(RwReg, 0xFFFFEC0CU) /**< \brief (DMAC) DMAC Software Chunk Transfer Request Register */
#define REG_DMAC_LAST          REG_ACCESS(RwReg, 0xFFFFEC10U) /**< \brief (DMAC) DMAC Software Last Transfer Flag Register */
#define REG_DMAC_EBCIER        REG_ACCESS(WoReg, 0xFFFFEC18U) /**< \brief (DMAC) DMAC Error, Chained Buffer Transfer Completed Interrupt and Buffer Transfer Completed Interrupt Enable register. */
#define REG_DMAC_EBCIDR        REG_ACCESS(WoReg, 0xFFFFEC1CU) /**< \brief (DMAC) DMAC Error, Chained Buffer Transfer Completed Interrupt and Buffer Transfer Completed Interrupt Disable register. */
#define REG_DMAC_EBCIMR        REG_ACCESS(RoReg, 0xFFFFEC20U) /**< \brief (DMAC) DMAC Error, Chained Buffer Transfer Completed Interrupt and Buffer transfer completed Mask Register. */
#define REG_DMAC_EBCISR        REG_ACCESS(RoReg, 0xFFFFEC24U) /**< \brief (DMAC) DMAC Error, Chained Buffer Transfer Completed Interrupt and Buffer transfer completed Status Register. */
#define REG_DMAC_CHER          REG_ACCESS(WoReg, 0xFFFFEC28U) /**< \brief (DMAC) DMAC Channel Handler Enable Register */
#define REG_DMAC_CHDR          REG_ACCESS(WoReg, 0xFFFFEC2CU) /**< \brief (DMAC) DMAC Channel Handler Disable Register */
#define REG_DMAC_CHSR          REG_ACCESS(RoReg, 0xFFFFEC30U) /**< \brief (DMAC) DMAC Channel Handler Status Register */
#define REG_DMAC_SADDR0        REG_ACCESS(RwReg, 0xFFFFEC3CU) /**< \brief (DMAC) DMAC Channel Source Address Register (ch_num = 0) */
#define REG_DMAC_DADDR0        REG_ACCESS(RwReg, 0xFFFFEC40U) /**< \brief (DMAC) DMAC Channel Destination Address Register (ch_num = 0) */
#define REG_DMAC_DSCR0         REG_ACCESS(RwReg, 0xFFFFEC44U) /**< \brief (DMAC) DMAC Channel Descriptor Address Register (ch_num = 0) */
#define REG_DMAC_CTRLA0        REG_ACCESS(RwReg, 0xFFFFEC48U) /**< \brief (DMAC) DMAC Channel Control A Register (ch_num = 0) */
#define REG_DMAC_CTRLB0        REG_ACCESS(RwReg, 0xFFFFEC4CU) /**< \brief (DMAC) DMAC Channel Control B Register (ch_num = 0) */
#define REG_DMAC_CFG0          REG_ACCESS(RwReg, 0xFFFFEC50U) /**< \brief (DMAC) DMAC Channel Configuration Register (ch_num = 0) */
#define REG_DMAC_SPIP0         REG_ACCESS(RwReg, 0xFFFFEC54U) /**< \brief (DMAC) DMAC Channel Source Picture-in-Picture Configuration Register (ch_num = 0) */
#define REG_DMAC_DPIP0         REG_ACCESS(RwReg, 0xFFFFEC58U) /**< \brief (DMAC) DMAC Channel Destination Picture-in-Picture Configuration Register (ch_num = 0) */
#define REG_DMAC_SADDR1        REG_ACCESS(RwReg, 0xFFFFEC64U) /**< \brief (DMAC) DMAC Channel Source Address Register (ch_num = 1) */
#define REG_DMAC_DADDR1        REG_ACCESS(RwReg, 0xFFFFEC68U) /**< \brief (DMAC) DMAC Channel Destination Address Register (ch_num = 1) */
#define REG_DMAC_DSCR1         REG_ACCESS(RwReg, 0xFFFFEC6CU) /**< \brief (DMAC) DMAC Channel Descriptor Address Register (ch_num = 1) */
#define REG_DMAC_CTRLA1        REG_ACCESS(RwReg, 0xFFFFEC70U) /**< \brief (DMAC) DMAC Channel Control A Register (ch_num = 1) */
#define REG_DMAC_CTRLB1        REG_ACCESS(RwReg, 0xFFFFEC74U) /**< \brief (DMAC) DMAC Channel Control B Register (ch_num = 1) */
#define REG_DMAC_CFG1          REG_ACCESS(RwReg, 0xFFFFEC78U) /**< \brief (DMAC) DMAC Channel Configuration Register (ch_num = 1) */
#define REG_DMAC_SPIP1         REG_ACCESS(RwReg, 0xFFFFEC7CU) /**< \brief (DMAC) DMAC Channel Source Picture-in-Picture Configuration Register (ch_num = 1) */
#define REG_DMAC_DPIP1         REG_ACCESS(RwReg, 0xFFFFEC80U) /**< \brief (DMAC) DMAC Channel Destination Picture-in-Picture Configuration Register (ch_num = 1) */
#define REG_DMAC_SADDR2        REG_ACCESS(RwReg, 0xFFFFEC8CU) /**< \brief (DMAC) DMAC Channel Source Address Register (ch_num = 2) */
#define REG_DMAC_DADDR2        REG_ACCESS(RwReg, 0xFFFFEC90U) /**< \brief (DMAC) DMAC Channel Destination Address Register (ch_num = 2) */
#define REG_DMAC_DSCR2         REG_ACCESS(RwReg, 0xFFFFEC94U) /**< \brief (DMAC) DMAC Channel Descriptor Address Register (ch_num = 2) */
#define REG_DMAC_CTRLA2        REG_ACCESS(RwReg, 0xFFFFEC98U) /**< \brief (DMAC) DMAC Channel Control A Register (ch_num = 2) */
#define REG_DMAC_CTRLB2        REG_ACCESS(RwReg, 0xFFFFEC9CU) /**< \brief (DMAC) DMAC Channel Control B Register (ch_num = 2) */
#define REG_DMAC_CFG2          REG_ACCESS(RwReg, 0xFFFFECA0U) /**< \brief (DMAC) DMAC Channel Configuration Register (ch_num = 2) */
#define REG_DMAC_SPIP2         REG_ACCESS(RwReg, 0xFFFFECA4U) /**< \brief (DMAC) DMAC Channel Source Picture-in-Picture Configuration Register (ch_num = 2) */
#define REG_DMAC_DPIP2         REG_ACCESS(RwReg, 0xFFFFECA8U) /**< \brief (DMAC) DMAC Channel Destination Picture-in-Picture Configuration Register (ch_num = 2) */
#define REG_DMAC_SADDR3        REG_ACCESS(RwReg, 0xFFFFECB4U) /**< \brief (DMAC) DMAC Channel Source Address Register (ch_num = 3) */
#define REG_DMAC_DADDR3        REG_ACCESS(RwReg, 0xFFFFECB8U) /**< \brief (DMAC) DMAC Channel Destination Address Register (ch_num = 3) */
#define REG_DMAC_DSCR3         REG_ACCESS(RwReg, 0xFFFFECBCU) /**< \brief (DMAC) DMAC Channel Descriptor Address Register (ch_num = 3) */
#define REG_DMAC_CTRLA3        REG_ACCESS(RwReg, 0xFFFFECC0U) /**< \brief (DMAC) DMAC Channel Control A Register (ch_num = 3) */
#define REG_DMAC_CTRLB3        REG_ACCESS(RwReg, 0xFFFFECC4U) /**< \brief (DMAC) DMAC Channel Control B Register (ch_num = 3) */
#define REG_DMAC_CFG3          REG_ACCESS(RwReg, 0xFFFFECC8U) /**< \brief (DMAC) DMAC Channel Configuration Register (ch_num = 3) */
#define REG_DMAC_SPIP3         REG_ACCESS(RwReg, 0xFFFFECCCU) /**< \brief (DMAC) DMAC Channel Source Picture-in-Picture Configuration Register (ch_num = 3) */
#define REG_DMAC_DPIP3         REG_ACCESS(RwReg, 0xFFFFECD0U) /**< \brief (DMAC) DMAC Channel Destination Picture-in-Picture Configuration Register (ch_num = 3) */
#define REG_DMAC_SADDR4        REG_ACCESS(RwReg, 0xFFFFECDCU) /**< \brief (DMAC) DMAC Channel Source Address Register (ch_num = 4) */
#define REG_DMAC_DADDR4        REG_ACCESS(RwReg, 0xFFFFECE0U) /**< \brief (DMAC) DMAC Channel Destination Address Register (ch_num = 4) */
#define REG_DMAC_DSCR4         REG_ACCESS(RwReg, 0xFFFFECE4U) /**< \brief (DMAC) DMAC Channel Descriptor Address Register (ch_num = 4) */
#define REG_DMAC_CTRLA4        REG_ACCESS(RwReg, 0xFFFFECE8U) /**< \brief (DMAC) DMAC Channel Control A Register (ch_num = 4) */
#define REG_DMAC_CTRLB4        REG_ACCESS(RwReg, 0xFFFFECECU) /**< \brief (DMAC) DMAC Channel Control B Register (ch_num = 4) */
#define REG_DMAC_CFG4          REG_ACCESS(RwReg, 0xFFFFECF0U) /**< \brief (DMAC) DMAC Channel Configuration Register (ch_num = 4) */
#define REG_DMAC_SPIP4         REG_ACCESS(RwReg, 0xFFFFECF4U) /**< \brief (DMAC) DMAC Channel Source Picture-in-Picture Configuration Register (ch_num = 4) */
#define REG_DMAC_DPIP4         REG_ACCESS(RwReg, 0xFFFFECF8U) /**< \brief (DMAC) DMAC Channel Destination Picture-in-Picture Configuration Register (ch_num = 4) */
#define REG_DMAC_SADDR5        REG_ACCESS(RwReg, 0xFFFFED04U) /**< \brief (DMAC) DMAC Channel Source Address Register (ch_num = 5) */
#define REG_DMAC_DADDR5        REG_ACCESS(RwReg, 0xFFFFED08U) /**< \brief (DMAC) DMAC Channel Destination Address Register (ch_num = 5) */
#define REG_DMAC_DSCR5         REG_ACCESS(RwReg, 0xFFFFED0CU) /**< \brief (DMAC) DMAC Channel Descriptor Address Register (ch_num = 5) */
#define REG_DMAC_CTRLA5        REG_ACCESS(RwReg, 0xFFFFED10U) /**< \brief (DMAC) DMAC Channel Control A Register (ch_num = 5) */
#define REG_DMAC_CTRLB5        REG_ACCESS(RwReg, 0xFFFFED14U) /**< \brief (DMAC) DMAC Channel Control B Register (ch_num = 5) */
#define REG_DMAC_CFG5          REG_ACCESS(RwReg, 0xFFFFED18U) /**< \brief (DMAC) DMAC Channel Configuration Register (ch_num = 5) */
#define REG_DMAC_SPIP5         REG_ACCESS(RwReg, 0xFFFFED1CU) /**< \brief (DMAC) DMAC Channel Source Picture-in-Picture Configuration Register (ch_num = 5) */
#define REG_DMAC_DPIP5         REG_ACCESS(RwReg, 0xFFFFED20U) /**< \brief (DMAC) DMAC Channel Destination Picture-in-Picture Configuration Register (ch_num = 5) */
#define REG_DMAC_SADDR6        REG_ACCESS(RwReg, 0xFFFFED2CU) /**< \brief (DMAC) DMAC Channel Source Address Register (ch_num = 6) */
#define REG_DMAC_DADDR6        REG_ACCESS(RwReg, 0xFFFFED30U) /**< \brief (DMAC) DMAC Channel Destination Address Register (ch_num = 6) */
#define REG_DMAC_DSCR6         REG_ACCESS(RwReg, 0xFFFFED34U) /**< \brief (DMAC) DMAC Channel Descriptor Address Register (ch_num = 6) */
#define REG_DMAC_CTRLA6        REG_ACCESS(RwReg, 0xFFFFED38U) /**< \brief (DMAC) DMAC Channel Control A Register (ch_num = 6) */
#define REG_DMAC_CTRLB6        REG_ACCESS(RwReg, 0xFFFFED3CU) /**< \brief (DMAC) DMAC Channel Control B Register (ch_num = 6) */
#define REG_DMAC_CFG6          REG_ACCESS(RwReg, 0xFFFFED40U) /**< \brief (DMAC) DMAC Channel Configuration Register (ch_num = 6) */
#define REG_DMAC_SPIP6         REG_ACCESS(RwReg, 0xFFFFED44U) /**< \brief (DMAC) DMAC Channel Source Picture-in-Picture Configuration Register (ch_num = 6) */
#define REG_DMAC_DPIP6         REG_ACCESS(RwReg, 0xFFFFED48U) /**< \brief (DMAC) DMAC Channel Destination Picture-in-Picture Configuration Register (ch_num = 6) */
#define REG_DMAC_SADDR7        REG_ACCESS(RwReg, 0xFFFFED54U) /**< \brief (DMAC) DMAC Channel Source Address Register (ch_num = 7) */
#define REG_DMAC_DADDR7        REG_ACCESS(RwReg, 0xFFFFED58U) /**< \brief (DMAC) DMAC Channel Destination Address Register (ch_num = 7) */
#define REG_DMAC_DSCR7         REG_ACCESS(RwReg, 0xFFFFED5CU) /**< \brief (DMAC) DMAC Channel Descriptor Address Register (ch_num = 7) */
#define REG_DMAC_CTRLA7        REG_ACCESS(RwReg, 0xFFFFED60U) /**< \brief (DMAC) DMAC Channel Control A Register (ch_num = 7) */
#define REG_DMAC_CTRLB7        REG_ACCESS(RwReg, 0xFFFFED64U) /**< \brief (DMAC) DMAC Channel Control B Register (ch_num = 7) */
#define REG_DMAC_CFG7          REG_ACCESS(RwReg, 0xFFFFED68U) /**< \brief (DMAC) DMAC Channel Configuration Register (ch_num = 7) */
#define REG_DMAC_SPIP7         REG_ACCESS(RwReg, 0xFFFFED6CU) /**< \brief (DMAC) DMAC Channel Source Picture-in-Picture Configuration Register (ch_num = 7) */
#define REG_DMAC_DPIP7         REG_ACCESS(RwReg, 0xFFFFED70U) /**< \brief (DMAC) DMAC Channel Destination Picture-in-Picture Configuration Register (ch_num = 7) */
#define REG_DMAC_WPMR          REG_ACCESS(RwReg, 0xFFFFEDE4U) /**< \brief (DMAC) DMAC Write Protect Mode Register */
#define REG_DMAC_WPSR          REG_ACCESS(RoReg, 0xFFFFEDE8U) /**< \brief (DMAC) DMAC Write Protect Status Register */
/* ========== Register definition for AIC peripheral ========== */
#define REG_AIC_SMR            REG_ACCESS(RwReg, 0xFFFFF000U) /**< \brief (AIC) Source Mode Register */
#define REG_AIC_SVR            REG_ACCESS(RwReg, 0xFFFFF080U) /**< \brief (AIC) Source Vector Register */
#define REG_AIC_IVR            REG_ACCESS(RoReg, 0xFFFFF100U) /**< \brief (AIC) Interrupt Vector Register */
#define REG_AIC_FVR            REG_ACCESS(RoReg, 0xFFFFF104U) /**< \brief (AIC) FIQ Interrupt Vector Register */
#define REG_AIC_ISR            REG_ACCESS(RoReg, 0xFFFFF108U) /**< \brief (AIC) Interrupt Status Register */
#define REG_AIC_IPR            REG_ACCESS(RoReg, 0xFFFFF10CU) /**< \brief (AIC) Interrupt Pending Register */
#define REG_AIC_IMR            REG_ACCESS(RoReg, 0xFFFFF110U) /**< \brief (AIC) Interrupt Mask Register */
#define REG_AIC_CISR           REG_ACCESS(RoReg, 0xFFFFF114U) /**< \brief (AIC) Core Interrupt Status Register */
#define REG_AIC_IECR           REG_ACCESS(WoReg, 0xFFFFF120U) /**< \brief (AIC) Interrupt Enable Command Register */
#define REG_AIC_IDCR           REG_ACCESS(WoReg, 0xFFFFF124U) /**< \brief (AIC) Interrupt Disable Command Register */
#define REG_AIC_ICCR           REG_ACCESS(WoReg, 0xFFFFF128U) /**< \brief (AIC) Interrupt Clear Command Register */
#define REG_AIC_ISCR           REG_ACCESS(WoReg, 0xFFFFF12CU) /**< \brief (AIC) Interrupt Set Command Register */
#define REG_AIC_EOICR          REG_ACCESS(WoReg, 0xFFFFF130U) /**< \brief (AIC) End of Interrupt Command Register */
#define REG_AIC_SPU            REG_ACCESS(RwReg, 0xFFFFF134U) /**< \brief (AIC) Spurious Interrupt Vector Register */
#define REG_AIC_DCR            REG_ACCESS(RwReg, 0xFFFFF138U) /**< \brief (AIC) Debug Control Register */
#define REG_AIC_FFER           REG_ACCESS(WoReg, 0xFFFFF140U) /**< \brief (AIC) Fast Forcing Enable Register */
#define REG_AIC_FFDR           REG_ACCESS(WoReg, 0xFFFFF144U) /**< \brief (AIC) Fast Forcing Disable Register */
#define REG_AIC_FFSR           REG_ACCESS(RoReg, 0xFFFFF148U) /**< \brief (AIC) Fast Forcing Status Register */
#define REG_AIC_WPMR           REG_ACCESS(RwReg, 0xFFFFF1E4U) /**< \brief (AIC) Write Protect Mode Register */
#define REG_AIC_WPSR           REG_ACCESS(RoReg, 0xFFFFF1E8U) /**< \brief (AIC) Write Protect Status Register */
/* ========== Register definition for DBGU peripheral ========== */
#define REG_DBGU_CR            REG_ACCESS(WoReg, 0xFFFFF200U) /**< \brief (DBGU) Control Register */
#define REG_DBGU_MR            REG_ACCESS(RwReg, 0xFFFFF204U) /**< \brief (DBGU) Mode Register */
#define REG_DBGU_IER           REG_ACCESS(WoReg, 0xFFFFF208U) /**< \brief (DBGU) Interrupt Enable Register */
#define REG_DBGU_IDR           REG_ACCESS(WoReg, 0xFFFFF20CU) /**< \brief (DBGU) Interrupt Disable Register */
#define REG_DBGU_IMR           REG_ACCESS(RoReg, 0xFFFFF210U) /**< \brief (DBGU) Interrupt Mask Register */
#define REG_DBGU_SR            REG_ACCESS(RoReg, 0xFFFFF214U) /**< \brief (DBGU) Status Register */
#define REG_DBGU_RHR           REG_ACCESS(RoReg, 0xFFFFF218U) /**< \brief (DBGU) Receive Holding Register */
#define REG_DBGU_THR           REG_ACCESS(WoReg, 0xFFFFF21CU) /**< \brief (DBGU) Transmit Holding Register */
#define REG_DBGU_BRGR          REG_ACCESS(RwReg, 0xFFFFF220U) /**< \brief (DBGU) Baud Rate Generator Register */
#define REG_DBGU_CIDR          REG_ACCESS(RoReg, 0xFFFFF240U) /**< \brief (DBGU) Chip ID Register */
#define REG_DBGU_EXID          REG_ACCESS(RoReg, 0xFFFFF244U) /**< \brief (DBGU) Chip ID Extension Register */
#define REG_DBGU_FNR           REG_ACCESS(RwReg, 0xFFFFF248U) /**< \brief (DBGU) Force NTRST Register */
/* ========== Register definition for PIOA peripheral ========== */
#define REG_PIOA_PER           REG_ACCESS(WoReg, 0xFFFFF400U) /**< \brief (PIOA) PIO Enable Register */
#define REG_PIOA_PDR           REG_ACCESS(WoReg, 0xFFFFF404U) /**< \brief (PIOA) PIO Disable Register */
#define REG_PIOA_PSR           REG_ACCESS(RoReg, 0xFFFFF408U) /**< \brief (PIOA) PIO Status Register */
#define REG_PIOA_OER           REG_ACCESS(WoReg, 0xFFFFF410U) /**< \brief (PIOA) Output Enable Register */
#define REG_PIOA_ODR           REG_ACCESS(WoReg, 0xFFFFF414U) /**< \brief (PIOA) Output Disable Register */
#define REG_PIOA_OSR           REG_ACCESS(RoReg, 0xFFFFF418U) /**< \brief (PIOA) Output Status Register */
#define REG_PIOA_IFER          REG_ACCESS(WoReg, 0xFFFFF420U) /**< \brief (PIOA) Glitch Input Filter Enable Register */
#define REG_PIOA_IFDR          REG_ACCESS(WoReg, 0xFFFFF424U) /**< \brief (PIOA) Glitch Input Filter Disable Register */
#define REG_PIOA_IFSR          REG_ACCESS(RoReg, 0xFFFFF428U) /**< \brief (PIOA) Glitch Input Filter Status Register */
#define REG_PIOA_SODR          REG_ACCESS(WoReg, 0xFFFFF430U) /**< \brief (PIOA) Set Output Data Register */
#define REG_PIOA_CODR          REG_ACCESS(WoReg, 0xFFFFF434U) /**< \brief (PIOA) Clear Output Data Register */
#define REG_PIOA_ODSR          REG_ACCESS(RwReg, 0xFFFFF438U) /**< \brief (PIOA) Output Data Status Register */
#define REG_PIOA_PDSR          REG_ACCESS(RoReg, 0xFFFFF43CU) /**< \brief (PIOA) Pin Data Status Register */
#define REG_PIOA_IER           REG_ACCESS(WoReg, 0xFFFFF440U) /**< \brief (PIOA) Interrupt Enable Register */
#define REG_PIOA_IDR           REG_ACCESS(WoReg, 0xFFFFF444U) /**< \brief (PIOA) Interrupt Disable Register */
#define REG_PIOA_IMR           REG_ACCESS(RoReg, 0xFFFFF448U) /**< \brief (PIOA) Interrupt Mask Register */
#define REG_PIOA_ISR           REG_ACCESS(RoReg, 0xFFFFF44CU) /**< \brief (PIOA) Interrupt Status Register */
#define REG_PIOA_MDER          REG_ACCESS(WoReg, 0xFFFFF450U) /**< \brief (PIOA) Multi-driver Enable Register */
#define REG_PIOA_MDDR          REG_ACCESS(WoReg, 0xFFFFF454U) /**< \brief (PIOA) Multi-driver Disable Register */
#define REG_PIOA_MDSR          REG_ACCESS(RoReg, 0xFFFFF458U) /**< \brief (PIOA) Multi-driver Status Register */
#define REG_PIOA_PUDR          REG_ACCESS(WoReg, 0xFFFFF460U) /**< \brief (PIOA) Pull-up Disable Register */
#define REG_PIOA_PUER          REG_ACCESS(WoReg, 0xFFFFF464U) /**< \brief (PIOA) Pull-up Enable Register */
#define REG_PIOA_PUSR          REG_ACCESS(RoReg, 0xFFFFF468U) /**< \brief (PIOA) Pad Pull-up Status Register */
#define REG_PIOA_ABCDSR        REG_ACCESS(RwReg, 0xFFFFF470U) /**< \brief (PIOA) Peripheral Select Register */
#define REG_PIOA_IFSCDR        REG_ACCESS(WoReg, 0xFFFFF480U) /**< \brief (PIOA) Input Filter Slow Clock Disable Register */
#define REG_PIOA_IFSCER        REG_ACCESS(WoReg, 0xFFFFF484U) /**< \brief (PIOA) Input Filter Slow Clock Enable Register */
#define REG_PIOA_IFSCSR        REG_ACCESS(RoReg, 0xFFFFF488U) /**< \brief (PIOA) Input Filter Slow Clock Status Register */
#define REG_PIOA_SCDR          REG_ACCESS(RwReg, 0xFFFFF48CU) /**< \brief (PIOA) Slow Clock Divider Debouncing Register */
#define REG_PIOA_PPDDR         REG_ACCESS(WoReg, 0xFFFFF490U) /**< \brief (PIOA) Pad Pull-down Disable Register */
#define REG_PIOA_PPDER         REG_ACCESS(WoReg, 0xFFFFF494U) /**< \brief (PIOA) Pad Pull-down Enable Register */
#define REG_PIOA_PPDSR         REG_ACCESS(RoReg, 0xFFFFF498U) /**< \brief (PIOA) Pad Pull-down Status Register */
#define REG_PIOA_OWER          REG_ACCESS(WoReg, 0xFFFFF4A0U) /**< \brief (PIOA) Output Write Enable */
#define REG_PIOA_OWDR          REG_ACCESS(WoReg, 0xFFFFF4A4U) /**< \brief (PIOA) Output Write Disable */
#define REG_PIOA_OWSR          REG_ACCESS(RoReg, 0xFFFFF4A8U) /**< \brief (PIOA) Output Write Status Register */
#define REG_PIOA_AIMER         REG_ACCESS(WoReg, 0xFFFFF4B0U) /**< \brief (PIOA) Additional Interrupt Modes Enable Register */
#define REG_PIOA_AIMDR         REG_ACCESS(WoReg, 0xFFFFF4B4U) /**< \brief (PIOA) Additional Interrupt Modes Disables Register */
#define REG_PIOA_AIMMR         REG_ACCESS(RoReg, 0xFFFFF4B8U) /**< \brief (PIOA) Additional Interrupt Modes Mask Register */
#define REG_PIOA_ESR           REG_ACCESS(WoReg, 0xFFFFF4C0U) /**< \brief (PIOA) Edge Select Register */
#define REG_PIOA_LSR           REG_ACCESS(WoReg, 0xFFFFF4C4U) /**< \brief (PIOA) Level Select Register */
#define REG_PIOA_ELSR          REG_ACCESS(RoReg, 0xFFFFF4C8U) /**< \brief (PIOA) Edge/Level Status Register */
#define REG_PIOA_FELLSR        REG_ACCESS(WoReg, 0xFFFFF4D0U) /**< \brief (PIOA) Falling Edge/Low Level Select Register */
#define REG_PIOA_REHLSR        REG_ACCESS(WoReg, 0xFFFFF4D4U) /**< \brief (PIOA) Rising Edge/ High Level Select Register */
#define REG_PIOA_FRLHSR        REG_ACCESS(RoReg, 0xFFFFF4D8U) /**< \brief (PIOA) Fall/Rise - Low/High Status Register */
#define REG_PIOA_LOCKSR        REG_ACCESS(RoReg, 0xFFFFF4E0U) /**< \brief (PIOA) Lock Status */
#define REG_PIOA_WPMR          REG_ACCESS(RwReg, 0xFFFFF4E4U) /**< \brief (PIOA) Write Protect Mode Register */
#define REG_PIOA_WPSR          REG_ACCESS(RoReg, 0xFFFFF4E8U) /**< \brief (PIOA) Write Protect Status Register */
#define REG_PIOA_SCHMITT       REG_ACCESS(RwReg, 0xFFFFF500U) /**< \brief (PIOA) Schmitt Trigger Register */
#define REG_PIOA_DELAYR        REG_ACCESS(RwReg, 0xFFFFF510U) /**< \brief (PIOA) IO Delay Register */
#define REG_PIOA_DRIVER1       REG_ACCESS(RwReg, 0xFFFFF514U) /**< \brief (PIOA) I/O Drive Register 1 */
#define REG_PIOA_DRIVER2       REG_ACCESS(RwReg, 0xFFFFF518U) /**< \brief (PIOA) I/O Drive Register 2 */
/* ========== Register definition for PIOB peripheral ========== */
#define REG_PIOB_PER           REG_ACCESS(WoReg, 0xFFFFF600U) /**< \brief (PIOB) PIO Enable Register */
#define REG_PIOB_PDR           REG_ACCESS(WoReg, 0xFFFFF604U) /**< \brief (PIOB) PIO Disable Register */
#define REG_PIOB_PSR           REG_ACCESS(RoReg, 0xFFFFF608U) /**< \brief (PIOB) PIO Status Register */
#define REG_PIOB_OER           REG_ACCESS(WoReg, 0xFFFFF610U) /**< \brief (PIOB) Output Enable Register */
#define REG_PIOB_ODR           REG_ACCESS(WoReg, 0xFFFFF614U) /**< \brief (PIOB) Output Disable Register */
#define REG_PIOB_OSR           REG_ACCESS(RoReg, 0xFFFFF618U) /**< \brief (PIOB) Output Status Register */
#define REG_PIOB_IFER          REG_ACCESS(WoReg, 0xFFFFF620U) /**< \brief (PIOB) Glitch Input Filter Enable Register */
#define REG_PIOB_IFDR          REG_ACCESS(WoReg, 0xFFFFF624U) /**< \brief (PIOB) Glitch Input Filter Disable Register */
#define REG_PIOB_IFSR          REG_ACCESS(RoReg, 0xFFFFF628U) /**< \brief (PIOB) Glitch Input Filter Status Register */
#define REG_PIOB_SODR          REG_ACCESS(WoReg, 0xFFFFF630U) /**< \brief (PIOB) Set Output Data Register */
#define REG_PIOB_CODR          REG_ACCESS(WoReg, 0xFFFFF634U) /**< \brief (PIOB) Clear Output Data Register */
#define REG_PIOB_ODSR          REG_ACCESS(RwReg, 0xFFFFF638U) /**< \brief (PIOB) Output Data Status Register */
#define REG_PIOB_PDSR          REG_ACCESS(RoReg, 0xFFFFF63CU) /**< \brief (PIOB) Pin Data Status Register */
#define REG_PIOB_IER           REG_ACCESS(WoReg, 0xFFFFF640U) /**< \brief (PIOB) Interrupt Enable Register */
#define REG_PIOB_IDR           REG_ACCESS(WoReg, 0xFFFFF644U) /**< \brief (PIOB) Interrupt Disable Register */
#define REG_PIOB_IMR           REG_ACCESS(RoReg, 0xFFFFF648U) /**< \brief (PIOB) Interrupt Mask Register */
#define REG_PIOB_ISR           REG_ACCESS(RoReg, 0xFFFFF64CU) /**< \brief (PIOB) Interrupt Status Register */
#define REG_PIOB_MDER          REG_ACCESS(WoReg, 0xFFFFF650U) /**< \brief (PIOB) Multi-driver Enable Register */
#define REG_PIOB_MDDR          REG_ACCESS(WoReg, 0xFFFFF654U) /**< \brief (PIOB) Multi-driver Disable Register */
#define REG_PIOB_MDSR          REG_ACCESS(RoReg, 0xFFFFF658U) /**< \brief (PIOB) Multi-driver Status Register */
#define REG_PIOB_PUDR          REG_ACCESS(WoReg, 0xFFFFF660U) /**< \brief (PIOB) Pull-up Disable Register */
#define REG_PIOB_PUER          REG_ACCESS(WoReg, 0xFFFFF664U) /**< \brief (PIOB) Pull-up Enable Register */
#define REG_PIOB_PUSR          REG_ACCESS(RoReg, 0xFFFFF668U) /**< \brief (PIOB) Pad Pull-up Status Register */
#define REG_PIOB_ABCDSR        REG_ACCESS(RwReg, 0xFFFFF670U) /**< \brief (PIOB) Peripheral Select Register */
#define REG_PIOB_IFSCDR        REG_ACCESS(WoReg, 0xFFFFF680U) /**< \brief (PIOB) Input Filter Slow Clock Disable Register */
#define REG_PIOB_IFSCER        REG_ACCESS(WoReg, 0xFFFFF684U) /**< \brief (PIOB) Input Filter Slow Clock Enable Register */
#define REG_PIOB_IFSCSR        REG_ACCESS(RoReg, 0xFFFFF688U) /**< \brief (PIOB) Input Filter Slow Clock Status Register */
#define REG_PIOB_SCDR          REG_ACCESS(RwReg, 0xFFFFF68CU) /**< \brief (PIOB) Slow Clock Divider Debouncing Register */
#define REG_PIOB_PPDDR         REG_ACCESS(WoReg, 0xFFFFF690U) /**< \brief (PIOB) Pad Pull-down Disable Register */
#define REG_PIOB_PPDER         REG_ACCESS(WoReg, 0xFFFFF694U) /**< \brief (PIOB) Pad Pull-down Enable Register */
#define REG_PIOB_PPDSR         REG_ACCESS(RoReg, 0xFFFFF698U) /**< \brief (PIOB) Pad Pull-down Status Register */
#define REG_PIOB_OWER          REG_ACCESS(WoReg, 0xFFFFF6A0U) /**< \brief (PIOB) Output Write Enable */
#define REG_PIOB_OWDR          REG_ACCESS(WoReg, 0xFFFFF6A4U) /**< \brief (PIOB) Output Write Disable */
#define REG_PIOB_OWSR          REG_ACCESS(RoReg, 0xFFFFF6A8U) /**< \brief (PIOB) Output Write Status Register */
#define REG_PIOB_AIMER         REG_ACCESS(WoReg, 0xFFFFF6B0U) /**< \brief (PIOB) Additional Interrupt Modes Enable Register */
#define REG_PIOB_AIMDR         REG_ACCESS(WoReg, 0xFFFFF6B4U) /**< \brief (PIOB) Additional Interrupt Modes Disables Register */
#define REG_PIOB_AIMMR         REG_ACCESS(RoReg, 0xFFFFF6B8U) /**< \brief (PIOB) Additional Interrupt Modes Mask Register */
#define REG_PIOB_ESR           REG_ACCESS(WoReg, 0xFFFFF6C0U) /**< \brief (PIOB) Edge Select Register */
#define REG_PIOB_LSR           REG_ACCESS(WoReg, 0xFFFFF6C4U) /**< \brief (PIOB) Level Select Register */
#define REG_PIOB_ELSR          REG_ACCESS(RoReg, 0xFFFFF6C8U) /**< \brief (PIOB) Edge/Level Status Register */
#define REG_PIOB_FELLSR        REG_ACCESS(WoReg, 0xFFFFF6D0U) /**< \brief (PIOB) Falling Edge/Low Level Select Register */
#define REG_PIOB_REHLSR        REG_ACCESS(WoReg, 0xFFFFF6D4U) /**< \brief (PIOB) Rising Edge/ High Level Select Register */
#define REG_PIOB_FRLHSR        REG_ACCESS(RoReg, 0xFFFFF6D8U) /**< \brief (PIOB) Fall/Rise - Low/High Status Register */
#define REG_PIOB_LOCKSR        REG_ACCESS(RoReg, 0xFFFFF6E0U) /**< \brief (PIOB) Lock Status */
#define REG_PIOB_WPMR          REG_ACCESS(RwReg, 0xFFFFF6E4U) /**< \brief (PIOB) Write Protect Mode Register */
#define REG_PIOB_WPSR          REG_ACCESS(RoReg, 0xFFFFF6E8U) /**< \brief (PIOB) Write Protect Status Register */
#define REG_PIOB_SCHMITT       REG_ACCESS(RwReg, 0xFFFFF700U) /**< \brief (PIOB) Schmitt Trigger Register */
#define REG_PIOB_DELAYR        REG_ACCESS(RwReg, 0xFFFFF710U) /**< \brief (PIOB) IO Delay Register */
#define REG_PIOB_DRIVER1       REG_ACCESS(RwReg, 0xFFFFF714U) /**< \brief (PIOB) I/O Drive Register 1 */
#define REG_PIOB_DRIVER2       REG_ACCESS(RwReg, 0xFFFFF718U) /**< \brief (PIOB) I/O Drive Register 2 */
/* ========== Register definition for PIOC peripheral ========== */
#define REG_PIOC_PER           REG_ACCESS(WoReg, 0xFFFFF800U) /**< \brief (PIOC) PIO Enable Register */
#define REG_PIOC_PDR           REG_ACCESS(WoReg, 0xFFFFF804U) /**< \brief (PIOC) PIO Disable Register */
#define REG_PIOC_PSR           REG_ACCESS(RoReg, 0xFFFFF808U) /**< \brief (PIOC) PIO Status Register */
#define REG_PIOC_OER           REG_ACCESS(WoReg, 0xFFFFF810U) /**< \brief (PIOC) Output Enable Register */
#define REG_PIOC_ODR           REG_ACCESS(WoReg, 0xFFFFF814U) /**< \brief (PIOC) Output Disable Register */
#define REG_PIOC_OSR           REG_ACCESS(RoReg, 0xFFFFF818U) /**< \brief (PIOC) Output Status Register */
#define REG_PIOC_IFER          REG_ACCESS(WoReg, 0xFFFFF820U) /**< \brief (PIOC) Glitch Input Filter Enable Register */
#define REG_PIOC_IFDR          REG_ACCESS(WoReg, 0xFFFFF824U) /**< \brief (PIOC) Glitch Input Filter Disable Register */
#define REG_PIOC_IFSR          REG_ACCESS(RoReg, 0xFFFFF828U) /**< \brief (PIOC) Glitch Input Filter Status Register */
#define REG_PIOC_SODR          REG_ACCESS(WoReg, 0xFFFFF830U) /**< \brief (PIOC) Set Output Data Register */
#define REG_PIOC_CODR          REG_ACCESS(WoReg, 0xFFFFF834U) /**< \brief (PIOC) Clear Output Data Register */
#define REG_PIOC_ODSR          REG_ACCESS(RwReg, 0xFFFFF838U) /**< \brief (PIOC) Output Data Status Register */
#define REG_PIOC_PDSR          REG_ACCESS(RoReg, 0xFFFFF83CU) /**< \brief (PIOC) Pin Data Status Register */
#define REG_PIOC_IER           REG_ACCESS(WoReg, 0xFFFFF840U) /**< \brief (PIOC) Interrupt Enable Register */
#define REG_PIOC_IDR           REG_ACCESS(WoReg, 0xFFFFF844U) /**< \brief (PIOC) Interrupt Disable Register */
#define REG_PIOC_IMR           REG_ACCESS(RoReg, 0xFFFFF848U) /**< \brief (PIOC) Interrupt Mask Register */
#define REG_PIOC_ISR           REG_ACCESS(RoReg, 0xFFFFF84CU) /**< \brief (PIOC) Interrupt Status Register */
#define REG_PIOC_MDER          REG_ACCESS(WoReg, 0xFFFFF850U) /**< \brief (PIOC) Multi-driver Enable Register */
#define REG_PIOC_MDDR          REG_ACCESS(WoReg, 0xFFFFF854U) /**< \brief (PIOC) Multi-driver Disable Register */
#define REG_PIOC_MDSR          REG_ACCESS(RoReg, 0xFFFFF858U) /**< \brief (PIOC) Multi-driver Status Register */
#define REG_PIOC_PUDR          REG_ACCESS(WoReg, 0xFFFFF860U) /**< \brief (PIOC) Pull-up Disable Register */
#define REG_PIOC_PUER          REG_ACCESS(WoReg, 0xFFFFF864U) /**< \brief (PIOC) Pull-up Enable Register */
#define REG_PIOC_PUSR          REG_ACCESS(RoReg, 0xFFFFF868U) /**< \brief (PIOC) Pad Pull-up Status Register */
#define REG_PIOC_ABCDSR        REG_ACCESS(RwReg, 0xFFFFF870U) /**< \brief (PIOC) Peripheral Select Register */
#define REG_PIOC_IFSCDR        REG_ACCESS(WoReg, 0xFFFFF880U) /**< \brief (PIOC) Input Filter Slow Clock Disable Register */
#define REG_PIOC_IFSCER        REG_ACCESS(WoReg, 0xFFFFF884U) /**< \brief (PIOC) Input Filter Slow Clock Enable Register */
#define REG_PIOC_IFSCSR        REG_ACCESS(RoReg, 0xFFFFF888U) /**< \brief (PIOC) Input Filter Slow Clock Status Register */
#define REG_PIOC_SCDR          REG_ACCESS(RwReg, 0xFFFFF88CU) /**< \brief (PIOC) Slow Clock Divider Debouncing Register */
#define REG_PIOC_PPDDR         REG_ACCESS(WoReg, 0xFFFFF890U) /**< \brief (PIOC) Pad Pull-down Disable Register */
#define REG_PIOC_PPDER         REG_ACCESS(WoReg, 0xFFFFF894U) /**< \brief (PIOC) Pad Pull-down Enable Register */
#define REG_PIOC_PPDSR         REG_ACCESS(RoReg, 0xFFFFF898U) /**< \brief (PIOC) Pad Pull-down Status Register */
#define REG_PIOC_OWER          REG_ACCESS(WoReg, 0xFFFFF8A0U) /**< \brief (PIOC) Output Write Enable */
#define REG_PIOC_OWDR          REG_ACCESS(WoReg, 0xFFFFF8A4U) /**< \brief (PIOC) Output Write Disable */
#define REG_PIOC_OWSR          REG_ACCESS(RoReg, 0xFFFFF8A8U) /**< \brief (PIOC) Output Write Status Register */
#define REG_PIOC_AIMER         REG_ACCESS(WoReg, 0xFFFFF8B0U) /**< \brief (PIOC) Additional Interrupt Modes Enable Register */
#define REG_PIOC_AIMDR         REG_ACCESS(WoReg, 0xFFFFF8B4U) /**< \brief (PIOC) Additional Interrupt Modes Disables Register */
#define REG_PIOC_AIMMR         REG_ACCESS(RoReg, 0xFFFFF8B8U) /**< \brief (PIOC) Additional Interrupt Modes Mask Register */
#define REG_PIOC_ESR           REG_ACCESS(WoReg, 0xFFFFF8C0U) /**< \brief (PIOC) Edge Select Register */
#define REG_PIOC_LSR           REG_ACCESS(WoReg, 0xFFFFF8C4U) /**< \brief (PIOC) Level Select Register */
#define REG_PIOC_ELSR          REG_ACCESS(RoReg, 0xFFFFF8C8U) /**< \brief (PIOC) Edge/Level Status Register */
#define REG_PIOC_FELLSR        REG_ACCESS(WoReg, 0xFFFFF8D0U) /**< \brief (PIOC) Falling Edge/Low Level Select Register */
#define REG_PIOC_REHLSR        REG_ACCESS(WoReg, 0xFFFFF8D4U) /**< \brief (PIOC) Rising Edge/ High Level Select Register */
#define REG_PIOC_FRLHSR        REG_ACCESS(RoReg, 0xFFFFF8D8U) /**< \brief (PIOC) Fall/Rise - Low/High Status Register */
#define REG_PIOC_LOCKSR        REG_ACCESS(RoReg, 0xFFFFF8E0U) /**< \brief (PIOC) Lock Status */
#define REG_PIOC_WPMR          REG_ACCESS(RwReg, 0xFFFFF8E4U) /**< \brief (PIOC) Write Protect Mode Register */
#define REG_PIOC_WPSR          REG_ACCESS(RoReg, 0xFFFFF8E8U) /**< \brief (PIOC) Write Protect Status Register */
#define REG_PIOC_SCHMITT       REG_ACCESS(RwReg, 0xFFFFF900U) /**< \brief (PIOC) Schmitt Trigger Register */
#define REG_PIOC_DELAYR        REG_ACCESS(RwReg, 0xFFFFF910U) /**< \brief (PIOC) IO Delay Register */
#define REG_PIOC_DRIVER1       REG_ACCESS(RwReg, 0xFFFFF914U) /**< \brief (PIOC) I/O Drive Register 1 */
#define REG_PIOC_DRIVER2       REG_ACCESS(RwReg, 0xFFFFF918U) /**< \brief (PIOC) I/O Drive Register 2 */
/* ========== Register definition for PIOD peripheral ========== */
#define REG_PIOD_PER           REG_ACCESS(WoReg, 0xFFFFFA00U) /**< \brief (PIOD) PIO Enable Register */
#define REG_PIOD_PDR           REG_ACCESS(WoReg, 0xFFFFFA04U) /**< \brief (PIOD) PIO Disable Register */
#define REG_PIOD_PSR           REG_ACCESS(RoReg, 0xFFFFFA08U) /**< \brief (PIOD) PIO Status Register */
#define REG_PIOD_OER           REG_ACCESS(WoReg, 0xFFFFFA10U) /**< \brief (PIOD) Output Enable Register */
#define REG_PIOD_ODR           REG_ACCESS(WoReg, 0xFFFFFA14U) /**< \brief (PIOD) Output Disable Register */
#define REG_PIOD_OSR           REG_ACCESS(RoReg, 0xFFFFFA18U) /**< \brief (PIOD) Output Status Register */
#define REG_PIOD_IFER          REG_ACCESS(WoReg, 0xFFFFFA20U) /**< \brief (PIOD) Glitch Input Filter Enable Register */
#define REG_PIOD_IFDR          REG_ACCESS(WoReg, 0xFFFFFA24U) /**< \brief (PIOD) Glitch Input Filter Disable Register */
#define REG_PIOD_IFSR          REG_ACCESS(RoReg, 0xFFFFFA28U) /**< \brief (PIOD) Glitch Input Filter Status Register */
#define REG_PIOD_SODR          REG_ACCESS(WoReg, 0xFFFFFA30U) /**< \brief (PIOD) Set Output Data Register */
#define REG_PIOD_CODR          REG_ACCESS(WoReg, 0xFFFFFA34U) /**< \brief (PIOD) Clear Output Data Register */
#define REG_PIOD_ODSR          REG_ACCESS(RwReg, 0xFFFFFA38U) /**< \brief (PIOD) Output Data Status Register */
#define REG_PIOD_PDSR          REG_ACCESS(RoReg, 0xFFFFFA3CU) /**< \brief (PIOD) Pin Data Status Register */
#define REG_PIOD_IER           REG_ACCESS(WoReg, 0xFFFFFA40U) /**< \brief (PIOD) Interrupt Enable Register */
#define REG_PIOD_IDR           REG_ACCESS(WoReg, 0xFFFFFA44U) /**< \brief (PIOD) Interrupt Disable Register */
#define REG_PIOD_IMR           REG_ACCESS(RoReg, 0xFFFFFA48U) /**< \brief (PIOD) Interrupt Mask Register */
#define REG_PIOD_ISR           REG_ACCESS(RoReg, 0xFFFFFA4CU) /**< \brief (PIOD) Interrupt Status Register */
#define REG_PIOD_MDER          REG_ACCESS(WoReg, 0xFFFFFA50U) /**< \brief (PIOD) Multi-driver Enable Register */
#define REG_PIOD_MDDR          REG_ACCESS(WoReg, 0xFFFFFA54U) /**< \brief (PIOD) Multi-driver Disable Register */
#define REG_PIOD_MDSR          REG_ACCESS(RoReg, 0xFFFFFA58U) /**< \brief (PIOD) Multi-driver Status Register */
#define REG_PIOD_PUDR          REG_ACCESS(WoReg, 0xFFFFFA60U) /**< \brief (PIOD) Pull-up Disable Register */
#define REG_PIOD_PUER          REG_ACCESS(WoReg, 0xFFFFFA64U) /**< \brief (PIOD) Pull-up Enable Register */
#define REG_PIOD_PUSR          REG_ACCESS(RoReg, 0xFFFFFA68U) /**< \brief (PIOD) Pad Pull-up Status Register */
#define REG_PIOD_ABCDSR        REG_ACCESS(RwReg, 0xFFFFFA70U) /**< \brief (PIOD) Peripheral Select Register */
#define REG_PIOD_IFSCDR        REG_ACCESS(WoReg, 0xFFFFFA80U) /**< \brief (PIOD) Input Filter Slow Clock Disable Register */
#define REG_PIOD_IFSCER        REG_ACCESS(WoReg, 0xFFFFFA84U) /**< \brief (PIOD) Input Filter Slow Clock Enable Register */
#define REG_PIOD_IFSCSR        REG_ACCESS(RoReg, 0xFFFFFA88U) /**< \brief (PIOD) Input Filter Slow Clock Status Register */
#define REG_PIOD_SCDR          REG_ACCESS(RwReg, 0xFFFFFA8CU) /**< \brief (PIOD) Slow Clock Divider Debouncing Register */
#define REG_PIOD_PPDDR         REG_ACCESS(WoReg, 0xFFFFFA90U) /**< \brief (PIOD) Pad Pull-down Disable Register */
#define REG_PIOD_PPDER         REG_ACCESS(WoReg, 0xFFFFFA94U) /**< \brief (PIOD) Pad Pull-down Enable Register */
#define REG_PIOD_PPDSR         REG_ACCESS(RoReg, 0xFFFFFA98U) /**< \brief (PIOD) Pad Pull-down Status Register */
#define REG_PIOD_OWER          REG_ACCESS(WoReg, 0xFFFFFAA0U) /**< \brief (PIOD) Output Write Enable */
#define REG_PIOD_OWDR          REG_ACCESS(WoReg, 0xFFFFFAA4U) /**< \brief (PIOD) Output Write Disable */
#define REG_PIOD_OWSR          REG_ACCESS(RoReg, 0xFFFFFAA8U) /**< \brief (PIOD) Output Write Status Register */
#define REG_PIOD_AIMER         REG_ACCESS(WoReg, 0xFFFFFAB0U) /**< \brief (PIOD) Additional Interrupt Modes Enable Register */
#define REG_PIOD_AIMDR         REG_ACCESS(WoReg, 0xFFFFFAB4U) /**< \brief (PIOD) Additional Interrupt Modes Disables Register */
#define REG_PIOD_AIMMR         REG_ACCESS(RoReg, 0xFFFFFAB8U) /**< \brief (PIOD) Additional Interrupt Modes Mask Register */
#define REG_PIOD_ESR           REG_ACCESS(WoReg, 0xFFFFFAC0U) /**< \brief (PIOD) Edge Select Register */
#define REG_PIOD_LSR           REG_ACCESS(WoReg, 0xFFFFFAC4U) /**< \brief (PIOD) Level Select Register */
#define REG_PIOD_ELSR          REG_ACCESS(RoReg, 0xFFFFFAC8U) /**< \brief (PIOD) Edge/Level Status Register */
#define REG_PIOD_FELLSR        REG_ACCESS(WoReg, 0xFFFFFAD0U) /**< \brief (PIOD) Falling Edge/Low Level Select Register */
#define REG_PIOD_REHLSR        REG_ACCESS(WoReg, 0xFFFFFAD4U) /**< \brief (PIOD) Rising Edge/ High Level Select Register */
#define REG_PIOD_FRLHSR        REG_ACCESS(RoReg, 0xFFFFFAD8U) /**< \brief (PIOD) Fall/Rise - Low/High Status Register */
#define REG_PIOD_LOCKSR        REG_ACCESS(RoReg, 0xFFFFFAE0U) /**< \brief (PIOD) Lock Status */
#define REG_PIOD_WPMR          REG_ACCESS(RwReg, 0xFFFFFAE4U) /**< \brief (PIOD) Write Protect Mode Register */
#define REG_PIOD_WPSR          REG_ACCESS(RoReg, 0xFFFFFAE8U) /**< \brief (PIOD) Write Protect Status Register */
#define REG_PIOD_SCHMITT       REG_ACCESS(RwReg, 0xFFFFFB00U) /**< \brief (PIOD) Schmitt Trigger Register */
#define REG_PIOD_DELAYR        REG_ACCESS(RwReg, 0xFFFFFB10U) /**< \brief (PIOD) IO Delay Register */
#define REG_PIOD_DRIVER1       REG_ACCESS(RwReg, 0xFFFFFB14U) /**< \brief (PIOD) I/O Drive Register 1 */
#define REG_PIOD_DRIVER2       REG_ACCESS(RwReg, 0xFFFFFB18U) /**< \brief (PIOD) I/O Drive Register 2 */
/* ========== Register definition for PMC peripheral ========== */
#define REG_PMC_SCER           REG_ACCESS(WoReg, 0xFFFFFC00U) /**< \brief (PMC) System Clock Enable Register */
#define REG_PMC_SCDR           REG_ACCESS(WoReg, 0xFFFFFC04U) /**< \brief (PMC) System Clock Disable Register */
#define REG_PMC_SCSR           REG_ACCESS(RoReg, 0xFFFFFC08U) /**< \brief (PMC) System Clock Status Register */
#define REG_PMC_PCER           REG_ACCESS(WoReg, 0xFFFFFC10U) /**< \brief (PMC) Peripheral Clock Enable Register */
#define REG_PMC_PCDR           REG_ACCESS(WoReg, 0xFFFFFC14U) /**< \brief (PMC) Peripheral Clock Disable Register */
#define REG_PMC_PCSR           REG_ACCESS(RoReg, 0xFFFFFC18U) /**< \brief (PMC) Peripheral Clock Status Register */
#define REG_CKGR_MOR           REG_ACCESS(RwReg, 0xFFFFFC20U) /**< \brief (PMC) Main Oscillator Register */
#define REG_CKGR_MCFR          REG_ACCESS(RwReg, 0xFFFFFC24U) /**< \brief (PMC) Main Clock Frequency Register */
#define REG_CKGR_PLLAR         REG_ACCESS(RwReg, 0xFFFFFC28U) /**< \brief (PMC) PLLA Register */
#define REG_CKGR_PLLBR         REG_ACCESS(RwReg, 0xFFFFFC2CU) /**< \brief (PMC) PLLB Register */
#define REG_PMC_MCKR           REG_ACCESS(RwReg, 0xFFFFFC30U) /**< \brief (PMC) Master Clock Register */
#define REG_PMC_USB            REG_ACCESS(RwReg, 0xFFFFFC38U) /**< \brief (PMC) USB Clock Register */
#define REG_PMC_PCK            REG_ACCESS(RwReg, 0xFFFFFC40U) /**< \brief (PMC) Programmable Clock 0 Register */
#define REG_PMC_IER            REG_ACCESS(WoReg, 0xFFFFFC60U) /**< \brief (PMC) Interrupt Enable Register */
#define REG_PMC_IDR            REG_ACCESS(WoReg, 0xFFFFFC64U) /**< \brief (PMC) Interrupt Disable Register */
#define REG_PMC_SR             REG_ACCESS(RoReg, 0xFFFFFC68U) /**< \brief (PMC) Status Register */
#define REG_PMC_IMR            REG_ACCESS(RoReg, 0xFFFFFC6CU) /**< \brief (PMC) Interrupt Mask Register */
#define REG_PMC_PLLICPR        REG_ACCESS(WoReg, 0xFFFFFC80U) /**< \brief (PMC) PLL Charge Pump Current Register */
#define REG_PMC_WPMR           REG_ACCESS(RwReg, 0xFFFFFCE4U) /**< \brief (PMC) Write Protect Mode Register */
#define REG_PMC_WPSR           REG_ACCESS(RoReg, 0xFFFFFCE8U) /**< \brief (PMC) Write Protect Status Register */
#define REG_PMC_PCR            REG_ACCESS(RwReg, 0xFFFFFD0CU) /**< \brief (PMC) Peripheral Control Register */
/* ========== Register definition for RSTC peripheral ========== */
#define REG_RSTC_CR            REG_ACCESS(WoReg, 0xFFFFFE00U) /**< \brief (RSTC) Control Register */
#define REG_RSTC_SR            REG_ACCESS(RoReg, 0xFFFFFE04U) /**< \brief (RSTC) Status Register */
#define REG_RSTC_MR            REG_ACCESS(RwReg, 0xFFFFFE08U) /**< \brief (RSTC) Mode Register */
/* ========== Register definition for SHDWC peripheral ========== */
#define REG_SHDWC_CR           REG_ACCESS(WoReg, 0xFFFFFE10U) /**< \brief (SHDWC) Shutdown Control Register */
#define REG_SHDWC_MR           REG_ACCESS(RwReg, 0xFFFFFE14U) /**< \brief (SHDWC) Shutdown Mode Register */
#define REG_SHDWC_SR           REG_ACCESS(RoReg, 0xFFFFFE18U) /**< \brief (SHDWC) Shutdown Status Register */
/* ========== Register definition for PIT peripheral ========== */
#define REG_PIT_MR             REG_ACCESS(RwReg, 0xFFFFFE30U) /**< \brief (PIT) Mode Register */
#define REG_PIT_SR             REG_ACCESS(RoReg, 0xFFFFFE34U) /**< \brief (PIT) Status Register */
#define REG_PIT_PIVR           REG_ACCESS(RoReg, 0xFFFFFE38U) /**< \brief (PIT) Periodic Interval Value Register */
#define REG_PIT_PIIR           REG_ACCESS(RoReg, 0xFFFFFE3CU) /**< \brief (PIT) Periodic Interval Image Register */
/* ========== Register definition for WDT peripheral ========== */
#define REG_WDT_CR             REG_ACCESS(WoReg, 0xFFFFFE40U) /**< \brief (WDT) Control Register */
#define REG_WDT_MR             REG_ACCESS(RwReg, 0xFFFFFE44U) /**< \brief (WDT) Mode Register */
#define REG_WDT_SR             REG_ACCESS(RoReg, 0xFFFFFE48U) /**< \brief (WDT) Status Register */
/* ========== Register definition for GPBR peripheral ========== */
#define REG_GPBR_GPBR0         REG_ACCESS(RwReg, 0xFFFFFE60U) /**< \brief (GPBR) General Purpose Backup Register 0 */
#define REG_GPBR_GPBR1         REG_ACCESS(RwReg, 0xFFFFFE64U) /**< \brief (GPBR) General Purpose Backup Register 1 */
#define REG_GPBR_GPBR2         REG_ACCESS(RwReg, 0xFFFFFE68U) /**< \brief (GPBR) General Purpose Backup Register 2 */
#define REG_GPBR_GPBR3         REG_ACCESS(RwReg, 0xFFFFFE6CU) /**< \brief (GPBR) General Purpose Backup Register 3 */
/* ========== Register definition for RTC peripheral ========== */
#define REG_RTC_CR             REG_ACCESS(RwReg, 0xFFFFFEB0U) /**< \brief (RTC) Control Register */
#define REG_RTC_MR             REG_ACCESS(RwReg, 0xFFFFFEB4U) /**< \brief (RTC) Mode Register */
#define REG_RTC_TIMR           REG_ACCESS(RwReg, 0xFFFFFEB8U) /**< \brief (RTC) Time Register */
#define REG_RTC_CALR           REG_ACCESS(RwReg, 0xFFFFFEBCU) /**< \brief (RTC) Calendar Register */
#define REG_RTC_TIMALR         REG_ACCESS(RwReg, 0xFFFFFEC0U) /**< \brief (RTC) Time Alarm Register */
#define REG_RTC_CALALR         REG_ACCESS(RwReg, 0xFFFFFEC4U) /**< \brief (RTC) Calendar Alarm Register */
#define REG_RTC_SR             REG_ACCESS(RoReg, 0xFFFFFEC8U) /**< \brief (RTC) Status Register */
#define REG_RTC_SCCR           REG_ACCESS(WoReg, 0xFFFFFECCU) /**< \brief (RTC) Status Clear Command Register */
#define REG_RTC_IER            REG_ACCESS(WoReg, 0xFFFFFED0U) /**< \brief (RTC) Interrupt Enable Register */
#define REG_RTC_IDR            REG_ACCESS(WoReg, 0xFFFFFED4U) /**< \brief (RTC) Interrupt Disable Register */
#define REG_RTC_IMR            REG_ACCESS(RoReg, 0xFFFFFED8U) /**< \brief (RTC) Interrupt Mask Register */
#define REG_RTC_VER            REG_ACCESS(RoReg, 0xFFFFFEDCU) /**< \brief (RTC) Valid Entry Register */
/*@}*/

/* ************************************************************************** */
/*   PERIPHERAL ID DEFINITIONS FOR SAM9N12 */
/* ************************************************************************** */
/** \addtogroup SAM9N12_id Peripheral Ids Definitions */
/*@{*/

#define ID_FIQ    ( 0) /**< \brief Advanced Interrupt Controller (FIQ) */
#define ID_SYS    ( 1) /**< \brief System Controller Interrupt (SYS) */
#define ID_PIOA   ( 2) /**< \brief Parallel I/O Controller A and B (PIOA) */
#define ID_PIOB   ( 2) /**< \brief Parallel I/O Controller A and B (PIOB) */
#define ID_PIOC   ( 3) /**< \brief Parallel I/O Controller C and D (PIOC) */
#define ID_PIOD   ( 3) /**< \brief Parallel I/O Controller C and D (PIOD) */
#define ID_FUSE   ( 4) /**< \brief FUSE Controller (FUSE) */
#define ID_USART0 ( 5) /**< \brief USART 0 (USART0) */
#define ID_USART1 ( 6) /**< \brief USART 1 (USART1) */
#define ID_USART2 ( 7) /**< \brief USART 2 (USART2) */
#define ID_USART3 ( 8) /**< \brief USART 3 (USART3) */
#define ID_TWI0   ( 9) /**< \brief Two-Wire Interface 0 (TWI0) */
#define ID_TWI1   (10) /**< \brief Two-Wire Interface 1 (TWI1) */
#define ID_HSMCI  (12) /**< \brief High Speed Multimedia Card Interface (HSMCI) */
#define ID_SPI0   (13) /**< \brief Serial Peripheral Interface 0 (SPI0) */
#define ID_SPI1   (14) /**< \brief Serial Peripheral Interface 1 (SPI1) */
#define ID_UART0  (15) /**< \brief UART 0 (UART0) */
#define ID_UART1  (16) /**< \brief UART 1 (UART1) */
#define ID_TC0    (17) /**< \brief Timer Counter 0 (TC0) */
#define ID_TC1    (17) /**< \brief 1 (TC1) */
#define ID_PWM    (18) /**< \brief Pulse Width Modulation Controller (PWM) */
#define ID_ADC    (19) /**< \brief ADC Controller (ADC) */
#define ID_DMAC   (20) /**< \brief DMA Controller (DMAC) */
#define ID_UHP    (22) /**< \brief USB Host (UHP) */
#define ID_UDP    (23) /**< \brief USB Device (UDP) */
#define ID_LCDC   (25) /**< \brief LCD Controller (LCDC) */
#define ID_SSC    (28) /**< \brief Synchronous Serial Controller (SSC) */
#define ID_TRNG   (30) /**< \brief True Random Number Generator (TRNG) */
#define ID_IRQ    (31) /**< \brief Advanced Interrupt Controller (IRQ) */
/*@}*/

/* ************************************************************************** */
/*   BASE ADDRESS DEFINITIONS FOR SAM9N12 */
/* ************************************************************************** */
/** \addtogroup SAM9N12_base Peripheral Base Address Definitions */
/*@{*/

#define SPI0     CAST(Spi     , 0xF0000000U) /**< \brief (SPI0    ) Base Address */
#define SPI1     CAST(Spi     , 0xF0004000U) /**< \brief (SPI1    ) Base Address */
#define HSMCI    CAST(Hsmci   , 0xF0008000U) /**< \brief (HSMCI   ) Base Address */
#define SSC      CAST(Ssc     , 0xF0010000U) /**< \brief (SSC     ) Base Address */
#define TC0      CAST(Tc      , 0xF8008000U) /**< \brief (TC0     ) Base Address */
#define TC1      CAST(Tc      , 0xF800C000U) /**< \brief (TC1     ) Base Address */
#define TWI0     CAST(Twi     , 0xF8010000U) /**< \brief (TWI0    ) Base Address */
#define TWI1     CAST(Twi     , 0xF8014000U) /**< \brief (TWI1    ) Base Address */
#define USART0   CAST(Usart   , 0xF801C000U) /**< \brief (USART0  ) Base Address */
#define USART1   CAST(Usart   , 0xF8020000U) /**< \brief (USART1  ) Base Address */
#define USART2   CAST(Usart   , 0xF8024000U) /**< \brief (USART2  ) Base Address */
#define USART3   CAST(Usart   , 0xF8028000U) /**< \brief (USART3  ) Base Address */
#define PWM      CAST(Pwm     , 0xF8034000U) /**< \brief (PWM     ) Base Address */
#define LCDC     CAST(Lcdc    , 0xF8038000U) /**< \brief (LCDC    ) Base Address */
#define UDP      CAST(Udp     , 0xF803C000U) /**< \brief (UDP     ) Base Address */
#define UART0    CAST(Uart    , 0xF8040000U) /**< \brief (UART0   ) Base Address */
#define UART1    CAST(Uart    , 0xF8044000U) /**< \brief (UART1   ) Base Address */
#define TRNG     CAST(Trng    , 0xF8048000U) /**< \brief (TRNG    ) Base Address */
#define ADC      CAST(Adc     , 0xF804C000U) /**< \brief (ADC     ) Base Address */
#define FUSE     CAST(Fuse    , 0xFFFFDC00U) /**< \brief (FUSE    ) Base Address */
#define MATRIX   CAST(Matrix  , 0xFFFFDE00U) /**< \brief (MATRIX  ) Base Address */
#define PMECC    CAST(Pmecc   , 0xFFFFE000U) /**< \brief (PMECC   ) Base Address */
#define PMERRLOC CAST(Pmerrloc, 0xFFFFE600U) /**< \brief (PMERRLOC) Base Address */
#define DDRSDRC  CAST(Ddrsdrc , 0xFFFFE800U) /**< \brief (DDRSDRC ) Base Address */
#define SMC      CAST(Smc     , 0xFFFFEA00U) /**< \brief (SMC     ) Base Address */
#define DMAC     CAST(Dmac    , 0xFFFFEC00U) /**< \brief (DMAC    ) Base Address */
#define AIC      CAST(Aic     , 0xFFFFF000U) /**< \brief (AIC     ) Base Address */
#define DBGU     CAST(Dbgu    , 0xFFFFF200U) /**< \brief (DBGU    ) Base Address */
#define PIOA     CAST(Pio     , 0xFFFFF400U) /**< \brief (PIOA    ) Base Address */
#define PIOB     CAST(Pio     , 0xFFFFF600U) /**< \brief (PIOB    ) Base Address */
#define PIOC     CAST(Pio     , 0xFFFFF800U) /**< \brief (PIOC    ) Base Address */
#define PIOD     CAST(Pio     , 0xFFFFFA00U) /**< \brief (PIOD    ) Base Address */
#define PMC      CAST(Pmc     , 0xFFFFFC00U) /**< \brief (PMC     ) Base Address */
#define RSTC     CAST(Rstc    , 0xFFFFFE00U) /**< \brief (RSTC    ) Base Address */
#define SHDWC    CAST(Shdwc   , 0xFFFFFE10U) /**< \brief (SHDWC   ) Base Address */
#define PIT      CAST(Pit     , 0xFFFFFE30U) /**< \brief (PIT     ) Base Address */
#define WDT      CAST(Wdt     , 0xFFFFFE40U) /**< \brief (WDT     ) Base Address */
#define GPBR     CAST(Gpbr    , 0xFFFFFE60U) /**< \brief (GPBR    ) Base Address */
#define RTC      CAST(Rtc     , 0xFFFFFEB0U) /**< \brief (RTC     ) Base Address */
/*@}*/

/* ************************************************************************** */
/*   PIO DEFINITIONS FOR SAM9N12 */
/* ************************************************************************** */
/** \addtogroup SAM9N12_pio Peripheral Pio Definitions */
/*@{*/

#define PIO_PA0              (1u << 0)  /**< \brief Pin Controlled by PA0 */
#define PIO_PA1              (1u << 1)  /**< \brief Pin Controlled by PA1 */
#define PIO_PA2              (1u << 2)  /**< \brief Pin Controlled by PA2 */
#define PIO_PA3              (1u << 3)  /**< \brief Pin Controlled by PA3 */
#define PIO_PA4              (1u << 4)  /**< \brief Pin Controlled by PA4 */
#define PIO_PA5              (1u << 5)  /**< \brief Pin Controlled by PA5 */
#define PIO_PA6              (1u << 6)  /**< \brief Pin Controlled by PA6 */
#define PIO_PA7              (1u << 7)  /**< \brief Pin Controlled by PA7 */
#define PIO_PA8              (1u << 8)  /**< \brief Pin Controlled by PA8 */
#define PIO_PA9              (1u << 9)  /**< \brief Pin Controlled by PA9 */
#define PIO_PA10             (1u << 10) /**< \brief Pin Controlled by PA10 */
#define PIO_PA11             (1u << 11) /**< \brief Pin Controlled by PA11 */
#define PIO_PA12             (1u << 12) /**< \brief Pin Controlled by PA12 */
#define PIO_PA13             (1u << 13) /**< \brief Pin Controlled by PA13 */
#define PIO_PA14             (1u << 14) /**< \brief Pin Controlled by PA14 */
#define PIO_PA15             (1u << 15) /**< \brief Pin Controlled by PA15 */
#define PIO_PA16             (1u << 16) /**< \brief Pin Controlled by PA16 */
#define PIO_PA17             (1u << 17) /**< \brief Pin Controlled by PA17 */
#define PIO_PA18             (1u << 18) /**< \brief Pin Controlled by PA18 */
#define PIO_PA19             (1u << 19) /**< \brief Pin Controlled by PA19 */
#define PIO_PA20             (1u << 20) /**< \brief Pin Controlled by PA20 */
#define PIO_PA21             (1u << 21) /**< \brief Pin Controlled by PA21 */
#define PIO_PA22             (1u << 22) /**< \brief Pin Controlled by PA22 */
#define PIO_PA23             (1u << 23) /**< \brief Pin Controlled by PA23 */
#define PIO_PA24             (1u << 24) /**< \brief Pin Controlled by PA24 */
#define PIO_PA25             (1u << 25) /**< \brief Pin Controlled by PA25 */
#define PIO_PA26             (1u << 26) /**< \brief Pin Controlled by PA26 */
#define PIO_PA27             (1u << 27) /**< \brief Pin Controlled by PA27 */
#define PIO_PA28             (1u << 28) /**< \brief Pin Controlled by PA28 */
#define PIO_PA29             (1u << 29) /**< \brief Pin Controlled by PA29 */
#define PIO_PA30             (1u << 30) /**< \brief Pin Controlled by PA30 */
#define PIO_PA31             (1u << 31) /**< \brief Pin Controlled by PA31 */
#define PIO_PB0              (1u << 0)  /**< \brief Pin Controlled by PB0 */
#define PIO_PB1              (1u << 1)  /**< \brief Pin Controlled by PB1 */
#define PIO_PB2              (1u << 2)  /**< \brief Pin Controlled by PB2 */
#define PIO_PB3              (1u << 3)  /**< \brief Pin Controlled by PB3 */
#define PIO_PB4              (1u << 4)  /**< \brief Pin Controlled by PB4 */
#define PIO_PB5              (1u << 5)  /**< \brief Pin Controlled by PB5 */
#define PIO_PB6              (1u << 6)  /**< \brief Pin Controlled by PB6 */
#define PIO_PB7              (1u << 7)  /**< \brief Pin Controlled by PB7 */
#define PIO_PB8              (1u << 8)  /**< \brief Pin Controlled by PB8 */
#define PIO_PB9              (1u << 9)  /**< \brief Pin Controlled by PB9 */
#define PIO_PB10             (1u << 10) /**< \brief Pin Controlled by PB10 */
#define PIO_PB11             (1u << 11) /**< \brief Pin Controlled by PB11 */
#define PIO_PB12             (1u << 12) /**< \brief Pin Controlled by PB12 */
#define PIO_PB13             (1u << 13) /**< \brief Pin Controlled by PB13 */
#define PIO_PB14             (1u << 14) /**< \brief Pin Controlled by PB14 */
#define PIO_PB15             (1u << 15) /**< \brief Pin Controlled by PB15 */
#define PIO_PB16             (1u << 16) /**< \brief Pin Controlled by PB16 */
#define PIO_PB17             (1u << 17) /**< \brief Pin Controlled by PB17 */
#define PIO_PB18             (1u << 18) /**< \brief Pin Controlled by PB18 */
#define PIO_PC0              (1u << 0)  /**< \brief Pin Controlled by PC0 */
#define PIO_PC1              (1u << 1)  /**< \brief Pin Controlled by PC1 */
#define PIO_PC2              (1u << 2)  /**< \brief Pin Controlled by PC2 */
#define PIO_PC3              (1u << 3)  /**< \brief Pin Controlled by PC3 */
#define PIO_PC4              (1u << 4)  /**< \brief Pin Controlled by PC4 */
#define PIO_PC5              (1u << 5)  /**< \brief Pin Controlled by PC5 */
#define PIO_PC6              (1u << 6)  /**< \brief Pin Controlled by PC6 */
#define PIO_PC7              (1u << 7)  /**< \brief Pin Controlled by PC7 */
#define PIO_PC8              (1u << 8)  /**< \brief Pin Controlled by PC8 */
#define PIO_PC9              (1u << 9)  /**< \brief Pin Controlled by PC9 */
#define PIO_PC10             (1u << 10) /**< \brief Pin Controlled by PC10 */
#define PIO_PC11             (1u << 11) /**< \brief Pin Controlled by PC11 */
#define PIO_PC12             (1u << 12) /**< \brief Pin Controlled by PC12 */
#define PIO_PC13             (1u << 13) /**< \brief Pin Controlled by PC13 */
#define PIO_PC14             (1u << 14) /**< \brief Pin Controlled by PC14 */
#define PIO_PC15             (1u << 15) /**< \brief Pin Controlled by PC15 */
#define PIO_PC16             (1u << 16) /**< \brief Pin Controlled by PC16 */
#define PIO_PC17             (1u << 17) /**< \brief Pin Controlled by PC17 */
#define PIO_PC18             (1u << 18) /**< \brief Pin Controlled by PC18 */
#define PIO_PC19             (1u << 19) /**< \brief Pin Controlled by PC19 */
#define PIO_PC20             (1u << 20) /**< \brief Pin Controlled by PC20 */
#define PIO_PC21             (1u << 21) /**< \brief Pin Controlled by PC21 */
#define PIO_PC22             (1u << 22) /**< \brief Pin Controlled by PC22 */
#define PIO_PC23             (1u << 23) /**< \brief Pin Controlled by PC23 */
#define PIO_PC24             (1u << 24) /**< \brief Pin Controlled by PC24 */
#define PIO_PC25             (1u << 25) /**< \brief Pin Controlled by PC25 */
#define PIO_PC26             (1u << 26) /**< \brief Pin Controlled by PC26 */
#define PIO_PC27             (1u << 27) /**< \brief Pin Controlled by PC27 */
#define PIO_PC28             (1u << 28) /**< \brief Pin Controlled by PC28 */
#define PIO_PC29             (1u << 29) /**< \brief Pin Controlled by PC29 */
#define PIO_PC30             (1u << 30) /**< \brief Pin Controlled by PC30 */
#define PIO_PC31             (1u << 31) /**< \brief Pin Controlled by PC31 */
#define PIO_PD0              (1u << 0)  /**< \brief Pin Controlled by PD0 */
#define PIO_PD1              (1u << 1)  /**< \brief Pin Controlled by PD1 */
#define PIO_PD2              (1u << 2)  /**< \brief Pin Controlled by PD2 */
#define PIO_PD3              (1u << 3)  /**< \brief Pin Controlled by PD3 */
#define PIO_PD4              (1u << 4)  /**< \brief Pin Controlled by PD4 */
#define PIO_PD5              (1u << 5)  /**< \brief Pin Controlled by PD5 */
#define PIO_PD6              (1u << 6)  /**< \brief Pin Controlled by PD6 */
#define PIO_PD7              (1u << 7)  /**< \brief Pin Controlled by PD7 */
#define PIO_PD8              (1u << 8)  /**< \brief Pin Controlled by PD8 */
#define PIO_PD9              (1u << 9)  /**< \brief Pin Controlled by PD9 */
#define PIO_PD10             (1u << 10) /**< \brief Pin Controlled by PD10 */
#define PIO_PD11             (1u << 11) /**< \brief Pin Controlled by PD11 */
#define PIO_PD12             (1u << 12) /**< \brief Pin Controlled by PD12 */
#define PIO_PD13             (1u << 13) /**< \brief Pin Controlled by PD13 */
#define PIO_PD14             (1u << 14) /**< \brief Pin Controlled by PD14 */
#define PIO_PD15             (1u << 15) /**< \brief Pin Controlled by PD15 */
#define PIO_PD16             (1u << 16) /**< \brief Pin Controlled by PD16 */
#define PIO_PD17             (1u << 17) /**< \brief Pin Controlled by PD17 */
#define PIO_PD18             (1u << 18) /**< \brief Pin Controlled by PD18 */
#define PIO_PD19             (1u << 19) /**< \brief Pin Controlled by PD19 */
#define PIO_PD20             (1u << 20) /**< \brief Pin Controlled by PD20 */
#define PIO_PD21             (1u << 21) /**< \brief Pin Controlled by PD21 */
/* ========== Pio definition for ADC peripheral ========== */
#define PIO_PB11X1_AD0       (1u << 11) /**< \brief Adc signal: AD0 */ 
#define PIO_PB12X1_AD1       (1u << 12) /**< \brief Adc signal: AD1 */ 
#define PIO_PB9X1_AD10       (1u << 9)  /**< \brief Adc signal: AD10 */ 
#define PIO_PB10X1_AD11      (1u << 10) /**< \brief Adc signal: AD11 */ 
#define PIO_PB13X1_AD2       (1u << 13) /**< \brief Adc signal: AD2 */ 
#define PIO_PB14X1_AD3       (1u << 14) /**< \brief Adc signal: AD3 */ 
#define PIO_PB15X1_AD4       (1u << 15) /**< \brief Adc signal: AD4 */ 
#define PIO_PB16X1_AD5       (1u << 16) /**< \brief Adc signal: AD5 */ 
#define PIO_PB17X1_AD6       (1u << 17) /**< \brief Adc signal: AD6 */ 
#define PIO_PB6X1_AD7        (1u << 6)  /**< \brief Adc signal: AD7 */ 
#define PIO_PB7X1_AD8        (1u << 7)  /**< \brief Adc signal: AD8 */ 
#define PIO_PB8X1_AD9        (1u << 8)  /**< \brief Adc signal: AD9 */ 
#define PIO_PB18B_ADTRG      (1u << 18) /**< \brief Adc signal: ADTRG */ 
/* ========== Pio definition for AIC peripheral ========== */
#define PIO_PC31A_FIQ        (1u << 31) /**< \brief Aic signal: FIQ */ 
#define PIO_PB18A_IRQ        (1u << 18) /**< \brief Aic signal: IRQ */ 
/* ========== Pio definition for DBGU peripheral ========== */
#define PIO_PA9A_DRXD        (1u << 9)  /**< \brief Dbgu signal: DRXD */ 
#define PIO_PA10A_DTXD       (1u << 10) /**< \brief Dbgu signal: DTXD */ 
/* ========== Pio definition for EBI peripheral ========== */
#define PIO_PD15B_A20        (1u << 15) /**< \brief Ebi signal: A20 */ 
#define PIO_PD2A_A21_NANDALE (1u << 2)  /**< \brief Ebi signal: A21/NANDALE */ 
#define PIO_PD3A_A22_NANDCLE (1u << 3)  /**< \brief Ebi signal: A22/NANDCLE */ 
#define PIO_PD16B_A23        (1u << 16) /**< \brief Ebi signal: A23 */ 
#define PIO_PD17B_A24        (1u << 17) /**< \brief Ebi signal: A24 */ 
#define PIO_PD18B_A25        (1u << 18) /**< \brief Ebi signal: A25 */ 
#define PIO_PD6A_D16         (1u << 6)  /**< \brief Ebi signal: D16 */ 
#define PIO_PD7A_D17         (1u << 7)  /**< \brief Ebi signal: D17 */ 
#define PIO_PD8A_D18         (1u << 8)  /**< \brief Ebi signal: D18 */ 
#define PIO_PD9A_D19         (1u << 9)  /**< \brief Ebi signal: D19 */ 
#define PIO_PD10A_D20        (1u << 10) /**< \brief Ebi signal: D20 */ 
#define PIO_PD11A_D21        (1u << 11) /**< \brief Ebi signal: D21 */ 
#define PIO_PD12A_D22        (1u << 12) /**< \brief Ebi signal: D22 */ 
#define PIO_PD13A_D23        (1u << 13) /**< \brief Ebi signal: D23 */ 
#define PIO_PD14A_D24        (1u << 14) /**< \brief Ebi signal: D24 */ 
#define PIO_PD15A_D25        (1u << 15) /**< \brief Ebi signal: D25 */ 
#define PIO_PD16A_D26        (1u << 16) /**< \brief Ebi signal: D26 */ 
#define PIO_PD17A_D27        (1u << 17) /**< \brief Ebi signal: D27 */ 
#define PIO_PD18A_D28        (1u << 18) /**< \brief Ebi signal: D28 */ 
#define PIO_PD19A_D29        (1u << 19) /**< \brief Ebi signal: D29 */ 
#define PIO_PD20A_D30        (1u << 20) /**< \brief Ebi signal: D30 */ 
#define PIO_PD21A_D31        (1u << 21) /**< \brief Ebi signal: D31 */ 
#define PIO_PD0A_NANDOE      (1u << 0)  /**< \brief Ebi signal: NANDOE */ 
#define PIO_PD1A_NANDWE      (1u << 1)  /**< \brief Ebi signal: NANDWE */ 
#define PIO_PD19B_NCS2       (1u << 19) /**< \brief Ebi signal: NCS2 */ 
#define PIO_PD4A_NCS3        (1u << 4)  /**< \brief Ebi signal: NCS3 */ 
#define PIO_PD20B_NCS4       (1u << 20) /**< \brief Ebi signal: NCS4 */ 
#define PIO_PD21B_NCS5       (1u << 21) /**< \brief Ebi signal: NCS5 */ 
#define PIO_PD5A_NWAIT       (1u << 5)  /**< \brief Ebi signal: NWAIT */ 
/* ========== Pio definition for HSMCI peripheral ========== */
#define PIO_PA16A_MCCDA      (1u << 16) /**< \brief Hsmci signal: MCCDA */ 
#define PIO_PA17A_MCCK       (1u << 17) /**< \brief Hsmci signal: MCCK */ 
#define PIO_PA15A_MCDA0      (1u << 15) /**< \brief Hsmci signal: MCDA0 */ 
#define PIO_PA18A_MCDA1      (1u << 18) /**< \brief Hsmci signal: MCDA1 */ 
#define PIO_PA19A_MCDA2      (1u << 19) /**< \brief Hsmci signal: MCDA2 */ 
#define PIO_PA20A_MCDA3      (1u << 20) /**< \brief Hsmci signal: MCDA3 */ 
#define PIO_PA11B_MCDA4      (1u << 11) /**< \brief Hsmci signal: MCDA4 */ 
#define PIO_PA12B_MCDA5      (1u << 12) /**< \brief Hsmci signal: MCDA5 */ 
#define PIO_PA13B_MCDA6      (1u << 13) /**< \brief Hsmci signal: MCDA6 */ 
#define PIO_PA14B_MCDA7      (1u << 14) /**< \brief Hsmci signal: MCDA7 */ 
/* ========== Pio definition for LCDC peripheral ========== */
#define PIO_PC0A_LCDDAT0     (1u << 0)  /**< \brief Lcdc signal: LCDDAT0 */ 
#define PIO_PC1A_LCDDAT1     (1u << 1)  /**< \brief Lcdc signal: LCDDAT1 */ 
#define PIO_PC10A_LCDDAT10   (1u << 10) /**< \brief Lcdc signal: LCDDAT10 */ 
#define PIO_PC11A_LCDDAT11   (1u << 11) /**< \brief Lcdc signal: LCDDAT11 */ 
#define PIO_PC12A_LCDDAT12   (1u << 12) /**< \brief Lcdc signal: LCDDAT12 */ 
#define PIO_PC13A_LCDDAT13   (1u << 13) /**< \brief Lcdc signal: LCDDAT13 */ 
#define PIO_PC14A_LCDDAT14   (1u << 14) /**< \brief Lcdc signal: LCDDAT14 */ 
#define PIO_PC15A_LCDDAT15   (1u << 15) /**< \brief Lcdc signal: LCDDAT15 */ 
#define PIO_PC16A_LCDDAT16   (1u << 16) /**< \brief Lcdc signal: LCDDAT16 */ 
#define PIO_PC17A_LCDDAT17   (1u << 17) /**< \brief Lcdc signal: LCDDAT17 */ 
#define PIO_PC18A_LCDDAT18   (1u << 18) /**< \brief Lcdc signal: LCDDAT18 */ 
#define PIO_PC19A_LCDDAT19   (1u << 19) /**< \brief Lcdc signal: LCDDAT19 */ 
#define PIO_PC2A_LCDDAT2     (1u << 2)  /**< \brief Lcdc signal: LCDDAT2 */ 
#define PIO_PC20A_LCDDAT20   (1u << 20) /**< \brief Lcdc signal: LCDDAT20 */ 
#define PIO_PC21A_LCDDAT21   (1u << 21) /**< \brief Lcdc signal: LCDDAT21 */ 
#define PIO_PC22A_LCDDAT22   (1u << 22) /**< \brief Lcdc signal: LCDDAT22 */ 
#define PIO_PC23A_LCDDAT23   (1u << 23) /**< \brief Lcdc signal: LCDDAT23 */ 
#define PIO_PC3A_LCDDAT3     (1u << 3)  /**< \brief Lcdc signal: LCDDAT3 */ 
#define PIO_PC4A_LCDDAT4     (1u << 4)  /**< \brief Lcdc signal: LCDDAT4 */ 
#define PIO_PC5A_LCDDAT5     (1u << 5)  /**< \brief Lcdc signal: LCDDAT5 */ 
#define PIO_PC6A_LCDDAT6     (1u << 6)  /**< \brief Lcdc signal: LCDDAT6 */ 
#define PIO_PC7A_LCDDAT7     (1u << 7)  /**< \brief Lcdc signal: LCDDAT7 */ 
#define PIO_PC8A_LCDDAT8     (1u << 8)  /**< \brief Lcdc signal: LCDDAT8 */ 
#define PIO_PC9A_LCDDAT9     (1u << 9)  /**< \brief Lcdc signal: LCDDAT9 */ 
#define PIO_PC29A_LCDDEN     (1u << 29) /**< \brief Lcdc signal: LCDDEN */ 
#define PIO_PC24A_LCDDISP    (1u << 24) /**< \brief Lcdc signal: LCDDISP */ 
#define PIO_PC28A_LCDHSYNC   (1u << 28) /**< \brief Lcdc signal: LCDHSYNC */ 
#define PIO_PC30A_LCDPCK     (1u << 30) /**< \brief Lcdc signal: LCDPCK */ 
#define PIO_PC26A_LCDPWM     (1u << 26) /**< \brief Lcdc signal: LCDPWM */ 
#define PIO_PC27A_LCDVSYNC   (1u << 27) /**< \brief Lcdc signal: LCDVSYNC */ 
/* ========== Pio definition for PMC peripheral ========== */
#define PIO_PB10B_PCK0       (1u << 10) /**< \brief Pmc signal: PCK0 */ 
#define PIO_PC15C_PCK0       (1u << 15) /**< \brief Pmc signal: PCK0 */ 
#define PIO_PB9B_PCK1        (1u << 9)  /**< \brief Pmc signal: PCK1 */ 
#define PIO_PC31C_PCK1       (1u << 31) /**< \brief Pmc signal: PCK1 */ 
/* ========== Pio definition for PWM peripheral ========== */
#define PIO_PB11B_PWM0       (1u << 11) /**< \brief Pwm signal: PWM0 */ 
#define PIO_PC10C_PWM0       (1u << 10) /**< \brief Pwm signal: PWM0 */ 
#define PIO_PC18C_PWM0       (1u << 18) /**< \brief Pwm signal: PWM0 */ 
#define PIO_PB12B_PWM1       (1u << 12) /**< \brief Pwm signal: PWM1 */ 
#define PIO_PC11C_PWM1       (1u << 11) /**< \brief Pwm signal: PWM1 */ 
#define PIO_PC19C_PWM1       (1u << 19) /**< \brief Pwm signal: PWM1 */ 
#define PIO_PB13B_PWM2       (1u << 13) /**< \brief Pwm signal: PWM2 */ 
#define PIO_PC20C_PWM2       (1u << 20) /**< \brief Pwm signal: PWM2 */ 
#define PIO_PB14B_PWM3       (1u << 14) /**< \brief Pwm signal: PWM3 */ 
#define PIO_PC21C_PWM3       (1u << 21) /**< \brief Pwm signal: PWM3 */ 
/* ========== Pio definition for SPI0 peripheral ========== */
#define PIO_PA11A_SPI0_MISO  (1u << 11) /**< \brief Spi0 signal: SPI0_MISO */ 
#define PIO_PA12A_SPI0_MOSI  (1u << 12) /**< \brief Spi0 signal: SPI0_MOSI */ 
#define PIO_PA14A_SPI0_NPCS0 (1u << 14) /**< \brief Spi0 signal: SPI0_NPCS0 */ 
#define PIO_PA7B_SPI0_NPCS1  (1u << 7)  /**< \brief Spi0 signal: SPI0_NPCS1 */ 
#define PIO_PA1B_SPI0_NPCS2  (1u << 1)  /**< \brief Spi0 signal: SPI0_NPCS2 */ 
#define PIO_PB3B_SPI0_NPCS3  (1u << 3)  /**< \brief Spi0 signal: SPI0_NPCS3 */ 
#define PIO_PA13A_SPI0_SPCK  (1u << 13) /**< \brief Spi0 signal: SPI0_SPCK */ 
/* ========== Pio definition for SPI1 peripheral ========== */
#define PIO_PA21B_SPI1_MISO  (1u << 21) /**< \brief Spi1 signal: SPI1_MISO */ 
#define PIO_PA22B_SPI1_MOSI  (1u << 22) /**< \brief Spi1 signal: SPI1_MOSI */ 
#define PIO_PA8B_SPI1_NPCS0  (1u << 8)  /**< \brief Spi1 signal: SPI1_NPCS0 */ 
#define PIO_PA0B_SPI1_NPCS1  (1u << 0)  /**< \brief Spi1 signal: SPI1_NPCS1 */ 
#define PIO_PA31B_SPI1_NPCS2 (1u << 31) /**< \brief Spi1 signal: SPI1_NPCS2 */ 
#define PIO_PA30B_SPI1_NPCS3 (1u << 30) /**< \brief Spi1 signal: SPI1_NPCS3 */ 
#define PIO_PA23B_SPI1_SPCK  (1u << 23) /**< \brief Spi1 signal: SPI1_SPCK */ 
/* ========== Pio definition for SSC peripheral ========== */
#define PIO_PA27B_RD         (1u << 27) /**< \brief Ssc signal: RD */ 
#define PIO_PA29B_RF         (1u << 29) /**< \brief Ssc signal: RF */ 
#define PIO_PA28B_RK         (1u << 28) /**< \brief Ssc signal: RK */ 
#define PIO_PA26B_TD         (1u << 26) /**< \brief Ssc signal: TD */ 
#define PIO_PA25B_TF         (1u << 25) /**< \brief Ssc signal: TF */ 
#define PIO_PA24B_TK         (1u << 24) /**< \brief Ssc signal: TK */ 
/* ========== Pio definition for TC0 peripheral ========== */
#define PIO_PA24A_TCLK0      (1u << 24) /**< \brief Tc0 signal: TCLK0 */ 
#define PIO_PA25A_TCLK1      (1u << 25) /**< \brief Tc0 signal: TCLK1 */ 
#define PIO_PA26A_TCLK2      (1u << 26) /**< \brief Tc0 signal: TCLK2 */ 
#define PIO_PA21A_TIOA0      (1u << 21) /**< \brief Tc0 signal: TIOA0 */ 
#define PIO_PA22A_TIOA1      (1u << 22) /**< \brief Tc0 signal: TIOA1 */ 
#define PIO_PA23A_TIOA2      (1u << 23) /**< \brief Tc0 signal: TIOA2 */ 
#define PIO_PA27A_TIOB0      (1u << 27) /**< \brief Tc0 signal: TIOB0 */ 
#define PIO_PA28A_TIOB1      (1u << 28) /**< \brief Tc0 signal: TIOB1 */ 
#define PIO_PA29A_TIOB2      (1u << 29) /**< \brief Tc0 signal: TIOB2 */ 
/* ========== Pio definition for TC1 peripheral ========== */
#define PIO_PC4C_TCLK3       (1u << 4)  /**< \brief Tc1 signal: TCLK3 */ 
#define PIO_PC7C_TCLK4       (1u << 7)  /**< \brief Tc1 signal: TCLK4 */ 
#define PIO_PC14C_TCLK5      (1u << 14) /**< \brief Tc1 signal: TCLK5 */ 
#define PIO_PC2C_TIOA3       (1u << 2)  /**< \brief Tc1 signal: TIOA3 */ 
#define PIO_PC5C_TIOA4       (1u << 5)  /**< \brief Tc1 signal: TIOA4 */ 
#define PIO_PC12C_TIOA5      (1u << 12) /**< \brief Tc1 signal: TIOA5 */ 
#define PIO_PC3C_TIOB3       (1u << 3)  /**< \brief Tc1 signal: TIOB3 */ 
#define PIO_PC6C_TIOB4       (1u << 6)  /**< \brief Tc1 signal: TIOB4 */ 
#define PIO_PC13C_TIOB5      (1u << 13) /**< \brief Tc1 signal: TIOB5 */ 
/* ========== Pio definition for TWI0 peripheral ========== */
#define PIO_PA31A_TWCK0      (1u << 31) /**< \brief Twi0 signal: TWCK0 */ 
#define PIO_PA30A_TWD0       (1u << 30) /**< \brief Twi0 signal: TWD0 */ 
/* ========== Pio definition for TWI1 peripheral ========== */
#define PIO_PC1C_TWCK1       (1u << 1)  /**< \brief Twi1 signal: TWCK1 */ 
#define PIO_PC0C_TWD1        (1u << 0)  /**< \brief Twi1 signal: TWD1 */ 
/* ========== Pio definition for UART0 peripheral ========== */
#define PIO_PC9C_URXD0       (1u << 9)  /**< \brief Uart0 signal: URXD0 */ 
#define PIO_PC8C_UTXD0       (1u << 8)  /**< \brief Uart0 signal: UTXD0 */ 
/* ========== Pio definition for UART1 peripheral ========== */
#define PIO_PC17C_URXD1      (1u << 17) /**< \brief Uart1 signal: URXD1 */ 
#define PIO_PC16C_UTXD1      (1u << 16) /**< \brief Uart1 signal: UTXD1 */ 
/* ========== Pio definition for USART0 peripheral ========== */
#define PIO_PA3A_CTS0        (1u << 3)  /**< \brief Usart0 signal: CTS0 */ 
#define PIO_PA2A_RTS0        (1u << 2)  /**< \brief Usart0 signal: RTS0 */ 
#define PIO_PA1A_RXD0        (1u << 1)  /**< \brief Usart0 signal: RXD0 */ 
#define PIO_PA4A_SCK0        (1u << 4)  /**< \brief Usart0 signal: SCK0 */ 
#define PIO_PA0A_TXD0        (1u << 0)  /**< \brief Usart0 signal: TXD0 */ 
/* ========== Pio definition for USART1 peripheral ========== */
#define PIO_PC28C_CTS1       (1u << 28) /**< \brief Usart1 signal: CTS1 */ 
#define PIO_PC27C_RTS1       (1u << 27) /**< \brief Usart1 signal: RTS1 */ 
#define PIO_PA6A_RXD1        (1u << 6)  /**< \brief Usart1 signal: RXD1 */ 
#define PIO_PC29C_SCK1       (1u << 29) /**< \brief Usart1 signal: SCK1 */ 
#define PIO_PA5A_TXD1        (1u << 5)  /**< \brief Usart1 signal: TXD1 */ 
/* ========== Pio definition for USART2 peripheral ========== */
#define PIO_PB1B_CTS2        (1u << 1)  /**< \brief Usart2 signal: CTS2 */ 
#define PIO_PB0B_RTS2        (1u << 0)  /**< \brief Usart2 signal: RTS2 */ 
#define PIO_PA8A_RXD2        (1u << 8)  /**< \brief Usart2 signal: RXD2 */ 
#define PIO_PB2B_SCK2        (1u << 2)  /**< \brief Usart2 signal: SCK2 */ 
#define PIO_PA7A_TXD2        (1u << 7)  /**< \brief Usart2 signal: TXD2 */ 
/* ========== Pio definition for USART3 peripheral ========== */
#define PIO_PC25B_CTS3       (1u << 25) /**< \brief Usart3 signal: CTS3 */ 
#define PIO_PC24B_RTS3       (1u << 24) /**< \brief Usart3 signal: RTS3 */ 
#define PIO_PC23B_RXD3       (1u << 23) /**< \brief Usart3 signal: RXD3 */ 
#define PIO_PC26B_SCK3       (1u << 26) /**< \brief Usart3 signal: SCK3 */ 
#define PIO_PC22B_TXD3       (1u << 22) /**< \brief Usart3 signal: TXD3 */ 
/*@}*/

/* ************************************************************************** */
/*   MEMORY MAPPING DEFINITIONS FOR SAM9N12 */
/* ************************************************************************** */


#define EBI_CS0_ADDR     (0x10000000u) /**< EBI Chip Select 0 base address */
#define EBI_CS1_ADDR     (0x20000000u) /**< EBI Chip Select 1 base address */
#define EBI_DDRSDRC_ADDR (0x20000000u) /**< DDR SDRAM Controller on EBI Chip Select 1 base address */
#define EBI_CS2_ADDR     (0x30000000u) /**< EBI Chip Select 2 base address */
#define EBI_CS3_ADDR     (0x40000000u) /**< EBI Chip Select 3 base address */
#define EBI_NF_ADDR      (0x40000000u) /**< NAND Flash on EBI Chip Select 3 base address */
#define EBI_CS4_ADDR     (0x50000000u) /**< EBI Chip Select 4 base address */
#define EBI_CS5_ADDR     (0x60000000u) /**< EBI Chip Select 5 base address */
#define IROM_ADDR        (0x00100000u) /**< Internal ROM base address */
#define IRAM_ADDR        (0x00300000u) /**< Internal RAM base address */

#ifdef __cplusplus
}
#endif

/*@}*/

#endif /* SAM9N12_H */
