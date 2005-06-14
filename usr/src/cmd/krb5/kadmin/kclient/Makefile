#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Makefile for Kerberos client-install utility.
#

PROG=	kclient
SRCS=	kclient.sh

include ../../../Makefile.cmd

POFILE=		$(SRCS:%.sh=%.po)

KCLIENTPROG=	$(PROG:%=$(KRB5SBIN)/%)

$(KCLIENTPROG) := FILEMODE = 555

.KEEP_STATE:

all: $(PROG)

install: all $(KRB5SBIN) $(KCLIENTPROG)

$(KRB5SBIN):
	$(INS.dir)

$(KCLIENTPROG)/%: %
	$(INS.file)

lint:
	@echo "nothing to lint"

clean:
	$(RM) $(PROG)

include ../../../Makefile.targ
