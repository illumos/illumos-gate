#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

PROG=ntptrace

all: $(PROG) 

include ../../Makefile.cmd
include ../Makefile.cmd

.KEEP_STATE:

.PARALLEL:

CLOBBERFILES = $(ROOTUSRSBINPROG)

install: all $(ROOTUSRSBINPROG)

clean:

include ../../Makefile.targ
#
OBJS=	ntptrace.o version.o
SOURCE=	ntptrace.c
LDLIBS += $(LIBS) ../$(LIBNTP_A)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

lint:
	$(LINT.c) -x -u $(DEFS) $(INCL) $(SOURCE) $(LDLIBS)

clean:
	$(RM) $(OBJS) $(PROG)
