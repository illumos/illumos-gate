#
# Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"

include ../Makefile.tools
include ../../../Makefile.cmd.64

CFLAGS64 += -D_ELF64

LDLIBS64 += -L ../../lib/$(MACH64) -lipf

all: $(PROG) $(IPFPROG)

install: all $(ROOTIPF64) $(ROOTUSRSBINPROG64) \
	$(ROOTUSRSBINLINKS) $(ROOTIPFPROG64) $(ROOTIPFLINKS)
