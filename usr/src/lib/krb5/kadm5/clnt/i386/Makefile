#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

MAPDIR= ../spec/i386

include ../Makefile.com

DYNFLAGS += $(KRUNPATH) $(KMECHLIB)
LDLIBS += -L $(ROOTLIBDIR) -lgss -lnsl -lsocket -lc
 
install: all $(ROOTLIBS) $(ROOTLINKS)
