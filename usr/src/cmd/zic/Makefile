#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include		$(SRC)/cmd/Makefile.cmd
include		$(SRC)/cmd/Makefile.ctf
include		$(SRC)/cmd/zic/Makefile.common

KSHPROG=	tzselect
ROOTKSHPROG=	$(ROOTBIN)/$(KSHPROG)
CLOBBERFILES +=	$(KSHPROG)

# Message catalog
POFILE2=	tzselect.po
TEXT_DOMAIN2=	SUNW_OST_ZONEINFO
MSGDOMAIN2=	$(MSGROOT)/$(TEXT_DOMAIN2)

.KEEP_STATE:

all:		$(PROG) $(KSHPROG)

$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

install:	all $(ROOTUSRSBINPROG) $(ROOTKSHPROG)

clean:
		$(RM) $(OBJS)

lint:		lint_SRCS

include		$(SRC)/cmd/Makefile.targ
