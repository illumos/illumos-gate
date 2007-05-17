#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
#  Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

PROG=		chat
OBJS=		chat.o
SRCS=		$(OBJS:%.o=%.c)

include		../../../Makefile.cmd

CPPFLAGS +=	-DSOL2
LDFLAGS +=	$(MAPFILE.NGB:%=-M%)

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTPROG)

clean:
	$(RM) $(OBJS)

lint:	

include		../../../Makefile.targ
