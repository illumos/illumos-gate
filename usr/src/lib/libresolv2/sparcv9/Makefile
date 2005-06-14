#
# Copyright 1997-2002 Sun Microsystems, Inc. All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libresolv2/sparcv9/Makefile

MAPDIR=	../spec/sparcv9

include ../Makefile.com
include ../../Makefile.lib.64

# With the adition of BIND 8.3.3, the symbol table for 64 bit went over
# the limit for Kpic, so we've added -KPIC here, for just the 64 bit 
# library. This avoids compiling the 32-bit library with PIC unnecessarily.

sparcv9_C_PICFLAGS = -K PIC
sparcv9_CC_PICFLAGS = -KPIC

LIBS = $(DYNLIB) $(LINTLIB)

.KEEP_STATE:

all: $(LIBS)

install: all $(ROOTLIBS64) $(ROOTLINKS64)
