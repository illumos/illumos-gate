#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#

PROG=	pfild

OBJS=	pfild.o vas.o
SRCS=	$(OBJS:.o=.c)

include ../../Makefile.cmd
include ../Makefile.ipf

LDLIBS          += $(LIBBPF) -lsocket -lnsl
CFLAGS		+= -DNDEBUG -D_XOPEN_SOURCE=500 -D__EXTENSIONS__
CPPFLAGS        += -I. -DIPFILTER_LOOKUP -DIPFILTER_LOG
CLEANFILES	+= $(OBJS)

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG)

clean:
	-$(RM) $(OBJS) $(PROG)

lint:	lint_SRCS

include ../../Makefile.targ
