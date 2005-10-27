#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1990 by Sun Microsystems, Inc.
#
# cmd/face/HELP/mail/Makefile

include		../../../Makefile.cmd
include		../../src/Makefile.com

ROOTDIR=	$(ROOTVMSYS)/HELP/mail

HELPFILES=	T.hmail T.hmerror T.hsend1 T.hsend2 T.hsend3 T.hsend4 \
		T.nmail T.read T.smail

ROOTBIN=	$(HELPFILES:%=$(ROOTDIR)/%)

FILEMODE=	755

# install rules

$(ROOTDIR)/% : %
	$(INS.file)

.KEEP_STATE:

all: $(HELPFILES)

install: all $(ROOTDIR) $(ROOTBIN)

$(ROOTDIR):
	-$(INS.dir)

clean clobber lint:
