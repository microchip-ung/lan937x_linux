
# Tool suffix when cross-compiling
CROSS_COMPILE = arm-none-eabi-

# Compilation tools
AR = $(CROSS_COMPILE)ar
CC = $(CROSS_COMPILE)gcc
AS = $(CROSS_COMPILE)as
#LD = $(CROSS_COMPILE)ld
#SIZE = $(CROSS_COMPILE)size
NM = $(CROSS_COMPILE)nm
#OBJCOPY = $(CROSS_COMPILE)objcopy

# Flags

CFLAGS += -Wall -Wchar-subscripts -Wcomment -Wformat=2 -Wimplicit-int
CFLAGS += -Werror-implicit-function-declaration -Wmain -Wparentheses
CFLAGS += -Wsequence-point -Wreturn-type -Wswitch -Wtrigraphs -Wunused
CFLAGS += -Wuninitialized -Wunknown-pragmas -Wfloat-equal -Wundef
CFLAGS += -Wshadow -Wpointer-arith -Wbad-function-cast -Wwrite-strings
CFLAGS += -Wsign-compare -Waggregate-return -Wstrict-prototypes
CFLAGS += -Wmissing-prototypes -Wmissing-declarations
CFLAGS += -Wformat -Wmissing-format-attribute -Wno-deprecated-declarations
CFLAGS += -Wredundant-decls -Wnested-externs -Winline -Wlong-long
CFLAGS += -Wunreachable-code 


CFLAGS += -mlong-calls -ffunction-sections
CFLAGS += $(OPTIMIZATION) $(INCLUDES) -D$(CHIP) -DTRACE_LEVEL=$(TRACE_LEVEL) -DDYN_TRACES

ifeq (OFF,$(DYN))
CFLAGS += -UDYN_TRACES
endif

ifeq (ON,$(PMECC_ALGO_ROM))
CFLAGS += -DUSE_PMECC_EMBEDDED_ALGO
endif

# To reduce application size use only integer printf function.
#CFLAGS += -Dprintf=iprintf 

ASFLAGS = -Wall -g $(OPTIMIZATION) $(INCLUDES) -D$(CHIP) -D__ASSEMBLY__
LDFLAGS = -g $(OPTIMIZATION) -nostartfiles -Wl,-Map=$(OUTPUT).map,--cref,--gc-sections
