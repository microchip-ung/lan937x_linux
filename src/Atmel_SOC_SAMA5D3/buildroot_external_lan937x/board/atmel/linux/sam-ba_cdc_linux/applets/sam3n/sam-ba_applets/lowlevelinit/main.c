/* ----------------------------------------------------------------------------
 *         ATMEL Microcontroller Software Support
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

/*----------------------------------------------------------------------------
 *        Headers
 *----------------------------------------------------------------------------*/
#include "../common/applet.h"
#include <board.h>
#include <string.h>

/*----------------------------------------------------------------------------
 *        Local definitions
 *----------------------------------------------------------------------------*/
/* Initialization mode */
#define EK_MODE 0
#define USER_DEFINED_CRYSTAL 1
#define BYASS_MODE 2

/*----------------------------------------------------------------------------
 *        Local structures
 *----------------------------------------------------------------------------*/
/** 
 * \brief Structure for storing parameters for each command that can be performed by the applet.
 */
struct _Mailbox {

    /* Command send to the monitor to be executed. */
    uint32_t command;
    /* Returned status, updated at the end of the monitor execution. */
    uint32_t status;

    /* Input Arguments in the argument area */
    union {

        /* Input arguments for the Init command. */
        struct {

            /* Communication link used. */
            uint32_t comType;
            /* Trace level. */
            uint32_t traceLevel;
            /* Low initialization mode */
            uint32_t mode;
            /* frequency of user-defined crystal */
            uint32_t crystalFreq;
            /* frequency of external clock in bypass mode */
            uint32_t extClk;

        } inputInit;

        /* Output arguments for the Init command. */
        /* None */

        /* Input arguments for the Write command. */
        /* None */

        /* Output arguments for the Write command. */
        /* None */

        /* Input arguments for the Read command. */
        /* None */

        /* Output arguments for the Read command. */
        /* None */

        /* Input arguments for the Full Erase command. */
        /* NONE */

        /* Output arguments for the Full Erase command. */
        /* NONE */

        /* Input arguments for the Buffer Erase command. */
        /* None */

        /* Output arguments for the Buffer Erase command. */
        /* NONE */
    } argument;
};


/**
 * \brief  Configure the PMC if the frequency of the external oscillator is different from the one mounted on EK
 * \param crystalFreq  The frequency of the external oscillator
 */
static void user_defined_LowlevelInit (uint32_t crystalFreq)
{
    uint32_t mul, div, prescaler;

#if defined(SAM_BA)
    { asm volatile ("cpsid i"); }
#endif
    /* Set 6 FWS for Embedded Flash Access */
    EFC->EEFC_FMR = EEFC_FMR_FWS(6);
    /* Enable NRST reset */
    RSTC->RSTC_MR |= RSTC_MR_URSTEN;

    switch (crystalFreq) {
        /* When crystal frequency is 3 MHz */
        case 3000000:
            /* PLL Clock = 3 * 32 / 1 = 96MHz */
            mul = 32;
            div = 0x01;
            /* Processor Clock = PLL Clock / prescaler = 96MHz / 2 = 48MHz */
            prescaler = PMC_MCKR_PRES_CLK_2;
            break;

        /* When crystal frequency is 4 MHz */
        case 4000000:
            /* PLL Clock = 4 * 24 / 1 = 96MHz */
            mul = 24;
            div = 0x01;
            /* Processor Clock = PLL Clock / prescaler = 96MHz / 2 = 48MHz */
            prescaler = PMC_MCKR_PRES_CLK_2;
            break;
       
        /* When crystal frequency is 6.4 MHz */
        case 6400000:
            /* PLL Clock = 6.4 * 15 / 1 = 96MHz */
            mul = 15;
            div = 0x01;
            /* Processor Clock = PLL Clock / prescaler = 96MHz / 2 = 48MHz */
            prescaler = PMC_MCKR_PRES_CLK_2;
            break;

        /* When crystal frequency is 8 MHz */
        case 8000000:
            /* PLL Clock = 8 * 12 / 1 = 96MHz */
            mul = 12;
            div = 0x01;
            /* Processor Clock = PLL Clock / prescaler = 96MHz / 2 = 48MHz */
            prescaler = PMC_MCKR_PRES_CLK_2;
            break;

        /* When crystal frequency is 12MHz */
        case 12000000:
            /* PLL Clock = 12 * 8 / 1 = 96MHz */
            mul = 8;
            div = 0x01;
            /* Processor Clock = PLL Clock / prescaler = 96MHz / 2 = 48MHz */
            prescaler = PMC_MCKR_PRES_CLK_2;
            break;

        /* When crystal frequency is 16MHz */
        case 16000000:
            /* PLL Clock = 16 * 6  = 96MHz */
            mul = 6;
            div = 0x01;
            /* Processor Clock = PLL Clock / prescaler = 96MHz / 1 = 48MHz */
            prescaler = PMC_MCKR_PRES_CLK_2;
            break;
    
        default:
            /* PLL Clock = f * mul / 1 */
            mul = 96 / crystalFreq;
            div = 0x01;
            prescaler = PMC_MCKR_PRES_CLK;
            break;
    }
   

    /* Switch MCK to Slow clock  */
    PMC_SetMckSelection(PMC_MCKR_CSS_SLOW_CLK, PMC_MCKR_PRES_CLK);
    PMC_EnableExtOsc(); 
    /* Then, cofigure PLL and switch clock */
    PMC_ConfigureMckWithPll(mul, div, prescaler); 

}

/**
 * \brief  Configure the PMC in bypass mode. An external clock should be input to XIN as the source clock.
 *
 * \param extClk  The frequency of the external clock
 */
static void bypass_LowLevelInit (uint32_t extClk)
{
    uint32_t mul, div, prescaler;

#if defined(SAM_BA)
    { asm volatile ("cpsid i"); } 
#endif
    /* Set 6 FWS for Embedded Flash Access */
    EFC->EEFC_FMR = EEFC_FMR_FWS(6);
    /* Enable NRST reset */
    RSTC->RSTC_MR |= RSTC_MR_URSTEN;

   switch (extClk) {
        /* When crystal frequency is 3 MHz */
        case 3000000:
            /* PLL Clock = 3 * 32 / 1 = 96MHz */
            mul = 32;
            div = 0x01;
            /* Processor Clock = PLL Clock / prescaler = 96MHz / 2 = 48MHz */
            prescaler = PMC_MCKR_PRES_CLK_2;
            break;

        /* When crystal frequency is 4 MHz */
        case 4000000:
            /* PLL Clock = 4 * 24 / 1 = 96MHz */
            mul = 24;
            div = 0x01;
            /* Processor Clock = PLL Clock / prescaler = 96MHz / 2 = 48MHz */
            prescaler = PMC_MCKR_PRES_CLK_2;
            break;
       
        /* When crystal frequency is 6.4 MHz */
        case 6400000:
            /* PLL Clock = 6.4 * 15 / 1 = 96MHz */
            mul = 15;
            div = 0x01;
            /* Processor Clock = PLL Clock / prescaler = 96MHz / 2 = 48MHz */
            prescaler = PMC_MCKR_PRES_CLK_2;
            break;

        /* When crystal frequency is 8 MHz */
        case 8000000:
            /* PLL Clock = 8 * 12 / 1 = 96MHz */
            mul = 12;
            div = 0x01;
            /* Processor Clock = PLL Clock / prescaler = 96MHz / 2 = 48MHz */
            prescaler = PMC_MCKR_PRES_CLK_2;
            break;

        /* When crystal frequency is 12MHz */
        case 12000000:
            /* PLL Clock = 12 * 8 / 1 = 96MHz */
            mul = 8;
            div = 0x01;
            /* Processor Clock = PLL Clock / prescaler = 96MHz / 2 = 48MHz */
            prescaler = PMC_MCKR_PRES_CLK_2;
            break;

        /* When crystal frequency is 16MHz */
        case 16000000:
            /* PLL Clock = 16 * 6  = 96MHz */
            mul = 6;
            div = 0x01;
            /* Processor Clock = PLL Clock / prescaler = 96MHz / 1 = 48MHz */
            prescaler = PMC_MCKR_PRES_CLK_2;
            break;
    
        default:
            /* PLL Clock = f * mul / 1 */
            mul = 96 / extClk;
            div = 0x01;
            prescaler = PMC_MCKR_PRES_CLK;
            break;
    }
    /* Switch MCK to Slow clock  */
    PMC_SetMckSelection(PMC_MCKR_CSS_SLOW_CLK, PMC_MCKR_PRES_CLK);
    /* Disable unused clock to save power (optional) */
    PMC_DisableIntRC4_8_12MHz();
    /* First, Main Crystal Oscillator bypass */
    PMC_SelectExtBypassOsc();
    /* Then, cofigure PLLA and switch clock */
    PMC_ConfigureMckWithPll(mul, div, prescaler);
}

/**
 * \brief  Configure the PMC as EK setting
 */
static void EK_LowLevelInit (void)
{
    LowLevelInit();
}

/*----------------------------------------------------------------------------
 *         Global functions
 *----------------------------------------------------------------------------*/
/**
 * \brief  Applet main entry. This function decodes received command and executes it.
 *
 * \param argc  always 1
 * \param argv  Address of the argument area..
 */
int main(int argc, char **argv)
{
    struct _Mailbox *pMailbox = (struct _Mailbox *) argv;

    uint32_t mode, crystalFreq, extClk;
    uint32_t comType = 0;
    // ----------------------------------------------------------
    // INIT:
    // ----------------------------------------------------------
    if (pMailbox->command == APPLET_CMD_INIT) {

        mode = pMailbox->argument.inputInit.mode;
        crystalFreq = pMailbox->argument.inputInit.crystalFreq;
        extClk = pMailbox->argument.inputInit.extClk;
        comType = pMailbox->argument.inputInit.comType;

        switch (mode) {
        case EK_MODE: 
            EK_LowLevelInit();
            pMailbox->status = APPLET_SUCCESS;
            break;
        case USER_DEFINED_CRYSTAL:
            user_defined_LowlevelInit(crystalFreq);
            pMailbox->status = APPLET_SUCCESS;
            break;
        case BYASS_MODE:
            bypass_LowLevelInit(extClk);
            pMailbox->status = APPLET_SUCCESS;
            break;
        default:
            pMailbox->status = APPLET_DEV_UNKNOWN;
            break;
        }
    } else {
        pMailbox->status = APPLET_DEV_UNKNOWN;
    }

    UART_Configure(115200, BOARD_MCK);

    /* Notify the host application of the end of the command processing */
    pMailbox->command = ~(pMailbox->command);
    if (comType == DBGU_COM_TYPE) {
        UART_PutChar(0x6);
    }

    return 0;
}

