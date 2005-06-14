#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 2000-2001 by Sun Microsystems, Inc.
# All rights reserved.
#
# cmd/cmd-inet/usr.bin/pppstats/Makefile
#

PROG=		pppstats
OBJS=		pppstats.o
SRCS=		$(OBJS:%.o=%.c)

include		../../../Makefile.cmd

PPPFLAGS +=	-DSTREAMS -DINTERNAL_BUILD -DSOL2
CPPFLAGS +=	$(PPPFLAGS)

.KEEP_STATE:

.PARALLEL:	$(OBJS)

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTPROG)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

include		../../../Makefile.targ
