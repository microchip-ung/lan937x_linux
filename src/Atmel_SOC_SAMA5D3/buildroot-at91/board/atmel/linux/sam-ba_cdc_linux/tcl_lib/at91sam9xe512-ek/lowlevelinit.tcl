#  ----------------------------------------------------------------------------
#          ATMEL Microcontroller Software Support
#  ----------------------------------------------------------------------------
#  Copyright (c) 2012, Atmel Corporation
#
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#
#  - Redistributions of source code must retain the above copyright notice,
#  this list of conditions and the disclaimer below.
#
#  Atmel's name may not be used to endorse or promote products derived from
#  this software without specific prior written permission. 
#
#  DISCLAIMER: THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR
#  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
#  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
#  DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR ANY DIRECT, INDIRECT,
#  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
#  OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
#  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
#  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
#  EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#  ----------------------------------------------------------------------------

set mainOsc(crystalList) [list \
    "3000000" \
    "3276800" \
    "3686400" \
    "3840000" \
    "4000000" \
    "4433619" \
    "4915200" \
    "5000000" \
    "5242880" \
    "6000000" \
    "6144000" \
    "6400000" \
    "6553600" \
    "7159090" \
    "7372800" \
    "7864320" \
    "8000000" \
    "9830400" \
    "10000000"\
    "11059200"\
    "12000000"\
    "12288000"\
    "13560000"\
    "14318180"\
    "14745600"\
    "16000000"\
    "16367667"\
    "17734470"\
    "18432000"\
    "20000000" ]

set mainOsc(initOsc)  0
set mainOsc(initXal)  18432000

namespace eval LOWLEVEL {
    
    variable appletAddr          0x300000
    variable appletMailboxAddr   0x300004
    variable appletFileName      "$libPath(extLib)/$target(board)/applet-lowlevelinit-at91sam9xe512.bin"

}

proc LOWLEVEL::Init {} {

    global mainOsc
    global commandLineMode
    global target
    
    switch $mainOsc(mode) {
        bypassMode {
            set mode 2
        }
    
        boardCrystalMode {
            set mode 1
        }
    
        default {
            set mode 0
        }
    }
    
    if {[catch {GENERIC::Init $LOWLEVEL::appletAddr $LOWLEVEL::appletMailboxAddr $LOWLEVEL::appletFileName [list $::target(comType) $::target(traceLevel) $mode $mainOsc(osc) $mainOsc(xal)]} dummy_err] } {
        set continue no
        if {$commandLineMode == 0} {
            set continue [tk_messageBox -title "Low level init" -message "Low level initialization failed.\nLow level initialization is required to run applets.\nContinue anyway ?" -icon warning -type yesno]
        } else {
            puts "-E- Error during Low level initialization."
            puts "-E- Low level initialization is required to run applets."
            puts "-E- Connection abort!"
        }
        # Close link
        if {$continue == no} {
            TCL_Close $target(handle)
            exit
        }
    } else {
            puts "-I- Low level initialized"
    }
}

