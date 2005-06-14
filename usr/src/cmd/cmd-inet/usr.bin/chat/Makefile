#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 2000 by Sun Microsystems, Inc.
# All rights reserved.
#

PROG=		chat
OBJS=		chat.o
SRCS=		$(OBJS:%.o=%.c)

include		../../../Makefile.cmd

CPPFLAGS +=	-DSOL2

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTPROG)

clean:
	$(RM) $(OBJS)

lint:	

include		../../../Makefile.targ
