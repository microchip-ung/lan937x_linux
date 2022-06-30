/* ----------------------------------------------------------------------------
 *         ATMEL Microcontroller Software Support
 * ----------------------------------------------------------------------------
 * Copyright (c) 2010, Atmel Corporation
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

/**
 *  \file
 *
 *  \section Purpose
 *
 *  This file provides a basic API for PIO configuration and usage of
 *  user-controlled pins. Please refer to the board.h file for a list of
 *  available pin definitions.
 *
 *  \section Usage
 *
 *  -# Define a constant pin description array such as the following one, using
 *     the existing definitions provided by the board.h file if possible:
 *     \code
 *        const Pin pPins[] = {PIN_USART0_TXD, PIN_USART0_RXD};
 *     \endcode
 *     Alternatively, it is possible to add new pins by provided the full Pin
 *     structure:
 *     \code
 *     // Pin instance to configure PA10 & PA11 as inputs with the internal
 *     // pull-up enabled.
 *     const Pin pPins = {
 *          (1 << 10) | (1 << 11),
 *          REG_PIOA,
 *          ID_PIOA,
 *          PIO_INPUT,
 *          PIO_PULLUP
 *     };
 *     \endcode
 *  -# Configure a pin array by calling PIO_Configure() with a pointer to the
 *     array and its size (which is computed using the PIO_LISTSIZE macro).
 *  -# Change and get the value of a user-controlled pin using the PIO_Set,
 *     PIO_Clear and PIO_Get methods.
 *  -# Get the level being currently output by a user-controlled pin configured
 *     as an output using PIO_GetOutputDataStatus().
 */

#ifndef _PIO_
#define _PIO_

/*
 *         Headers
 */

#include "chip.h"

#include <stdint.h>

#ifdef __cplusplus
 extern "C" {
#endif

/*
 *         Global Definitions
 */

/**
 *  Definitions for pin usage types
 */
typedef enum _EPIO_PinType
{
/** The pin is controlled by the associated signal of peripheral A. */
    PIO_PERIPH_A=0u,   
/** The pin is controlled by the associated signal of peripheral B. */    
    PIO_PERIPH_B,   
/** The pin is an input. */    
    PIO_INPUT,   
/** The pin is an output and has a default level of 0. */    
    PIO_OUTPUT_0,   
 /** The pin is an output and has a default level of 1. */    
    PIO_OUTPUT_1            
} EPIO_PinType ;

/**
 *  Definitions to be used as attributes in PIO API functions calls
 */

 /** Default pin configuration (no attribute). */
#define PIO_DEFAULT                 (0u << 0) 
/** The internal pin pull-up is active. */
#define PIO_PULLUP                  (1u << 0)  
/** The internal glitch filter is active. */
#define PIO_DEGLITCH                (1u << 1)  
/** The pin is open-drain. */
#define PIO_OPENDRAIN               (1u << 2)  
/** The internal debouncing filter is active. */
#define PIO_DEBOUNCE                (1u << 3)  
/** Enable additional interrupt modes. */
#define PIO_IT_AIME                 (1u << 4)  
/** Interrupt High Level/Rising Edge detection is active. */
#define PIO_IT_RE_OR_HL             (1u << 5)  
/** Interrupt Edge detection is active. */
#define PIO_IT_EDGE                 (1u << 6)  
/** Low level interrupt is active */
#define PIO_IT_LOW_LEVEL            (0               | 0 | PIO_IT_AIME) 
/** High level interrupt is active */
#define PIO_IT_HIGH_LEVEL           (PIO_IT_RE_OR_HL | 0 | PIO_IT_AIME)
/** Falling edge interrupt is active */
#define PIO_IT_FALL_EDGE            (0               | PIO_IT_EDGE | PIO_IT_AIME) 
/** Rising edge interrupt is active */
#define PIO_IT_RISE_EDGE            (PIO_IT_RE_OR_HL | PIO_IT_EDGE | PIO_IT_AIME) 
/** The output is high. */
#define PIO_OUTPUT_HIGH             (1u << 7)  
 /** The output is low. */
#define PIO_OUTPUT_LOW              (0u << 7) 
 /** The WP is enable */
#define PIO_WPMR_WPEN_EN            ( 0x01     << 0 )
 /** The WP is disable */
#define PIO_WPMR_WPEN_DIS           ( 0x00     << 0 )
 /** Valid WP key */
#define PIO_WPMR_WPKEY_VALID        ( 0x50494F << 8 )
/*
 *         Global Functions
 */

extern void PIO_SetPeripheralA( Pio *pio, uint32_t dwMask, uint32_t dwOptions ) ;
extern void PIO_SetPeripheralB( Pio *pio, uint32_t dwMask, uint32_t dwOptions ) ;
extern void PIO_SetInput( Pio *pio, uint32_t dwMask, uint32_t dwAttributes ) ;
extern void PIO_SetOutput( Pio* pPio, uint32_t dwMask, uint32_t dwOptions ) ;

#ifdef __cplusplus
}
#endif

#endif /* #ifndef _PIO_ */

