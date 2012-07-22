#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
#  Use is subject to license terms.
#

PROG=		chat
OBJS=		chat.o
SRCS=		$(OBJS:%.o=%.c)

include		../../../Makefile.cmd

CPPFLAGS +=	-DSOL2
LDFLAGS +=	$(MAPFILE.NGB:%=-M%)
CERRWARN +=	-_gcc=-Wno-unused-value
CERRWARN +=	-_gcc=-Wno-trigraphs

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTPROG)

clean:
	$(RM) $(OBJS)

lint:	

include		../../../Makefile.targ
