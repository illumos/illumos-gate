#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

MAPDIR= ../spec/i386

include ../Makefile.com

# library dependency
DYNFLAGS += $(KRUNPATH) $(KMECHLIB)
DYNFLAGS += $(KRB5LIB)/libkdb.so $(KRB5LIB)/libdb2.so $(KRB5LIB)/libdyn.so
LDLIBS += -L $(ROOTLIBDIR) -lgss -lnsl -lc -lsocket

install: all $(ROOTLIBS) $(ROOTLINKS)
