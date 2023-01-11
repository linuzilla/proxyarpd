#

CC	= gcc
CCOPT	= -Wall -O2 -g
INCLS   = -DYYDEBUG=1
DEFS    =
LOPT    = -lpcre2-8


CFLAGS = $(CCOPT) $(INCLS) $(DEFS) $(OSDEPOPT)

SRC = main.c packet.c utils.c
OBJ = $(SRC:.c=.o)
VER := $(shell grep "^\#define PROXYARPD_VERSION" proxyarpd.h | awk '{print $$3}' |sed s:\"::g)
CLEANFILES = $(OBJ) proxyarpd 
GCCVER := $(shell gcc -v 2>&1 | grep "gcc version" | awk '{print $$3}')
OSREL  := $(shell uname -r | sed 's/\([.0-9]*\).*/\1/')
# CFLAGS += -DGCC_VERSION=\"$(GCCVER)\" -DOS_RELEASE=\"$(OSREL)\"
# CFLAGS += -DCHIPLINUX_VERSION=\"$(VER)\"

.c.o:
	@rm -f $@
	$(CC) $(CFLAGS) -c $*.c

all: proxyarpd

proxyarpd:	$(OBJ)
	@rm -f $@
	$(CC) $(CFLAGS) -Wno-unused-function -s -o $@ $(OBJ) $(LOPT)

clean:
	rm -f $(CLEANFILES)
