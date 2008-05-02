#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

PROG= ntpdate

all: $(PROG) 

include ../../Makefile.cmd
include ../Makefile.cmd

.KEEP_STATE:

.PARALLEL:

CLOBBERFILES = $(ROOTUSRSBINPROG)

install: all $(ROOTUSRSBINPROG)

clean:

include ../../Makefile.targ

LDLIBS += ../$(LIBNTP_A) $(LIBS) -lmd

OBJS=	ntpdate.o version.o
SOURCE=	ntpdate.c

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

lint:
	$(LINT.c) -x -u $(DEFS) $(INCL) $(SOURCE) $(LDLIBS)

clean:
	$(RM) $(OBJS) $(PROG)
