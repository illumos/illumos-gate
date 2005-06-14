#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

MAPDIR= ../spec/sparcv9

include ../Makefile.com
include ../../../../Makefile.lib.64

DYNFLAGS += $(KRUNPATH64) $(KMECHLIB64)
LDLIBS += -L $(ROOTLIBDIR) -lgss -lnsl -lsocket -lc

install: all $(ROOTLIBDIR64) $(ROOTLIBS64) $(ROOTLINKS64)
