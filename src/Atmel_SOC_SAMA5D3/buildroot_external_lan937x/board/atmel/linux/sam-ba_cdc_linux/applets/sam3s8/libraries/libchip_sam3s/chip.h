#ifndef _LIB_SAM3S_
#define _LIB_SAM3S_

/*
 * Peripherals registers definitions
 */
#if defined(sam3s8) || defined(sam3sd8)
    #include "include/SAM3S8.h"
#elif defined sam3s16
    #include "include/SAM3S16.h"
#else
    #warning Library does not support the specified chip, specifying sam3sd8.
    #define sam3sd8
    #include "include/SAM3S8.h"
#endif

/* Define attribute */
#if defined   ( __CC_ARM   ) /* Keil �Vision 4 */
    #define WEAK __attribute__ ((weak))
#elif defined ( __ICCARM__ ) /* IAR Ewarm 5.41+ */
    #define WEAK __weak
#elif defined (  __GNUC__  ) /* GCC CS3 2009q3-68 */
    #define WEAK __attribute__ ((weak))
#endif

/* Define NO_INIT attribute */
#if defined   ( __CC_ARM   )
    #define NO_INIT
#elif defined ( __ICCARM__ )
    #define NO_INIT __no_init
#elif defined (  __GNUC__  )
    #define NO_INIT
#endif

/* Define RAMFUNC attribute */
#ifdef __ICCARM__
#define RAMFUNC __ramfunc
#else
#define RAMFUNC __attribute__ ((section (".ramfunc")))
#endif

/*
 * Peripherals
 */
#include "include/efc.h"
#include "include/flashd.h"
#include "include/pio.h"
#include "include/pmc.h"
#include "include/usart.h"
#include "include/trace.h"
#include "include/wdt.h"

#endif /* _LIB_SAM3S_ */

