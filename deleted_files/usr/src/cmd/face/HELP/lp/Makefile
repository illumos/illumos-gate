#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1990 by Sun Microsystems, Inc.
#
# cmd/face/HELP/lp/Makefile

include		../../../Makefile.cmd
include		../../src/Makefile.com

ROOTDIR=	$(ROOTVMSYS)/HELP/lp

HELPFILES=	T.hlpops

ROOTBIN=	$(HELPFILES:%=$(ROOTDIR)/%)

FILEMODE=	755

#install rules

$(ROOTDIR)/% : %
	$(INS.file)

.KEEP_STATE:

all: $(HELPFILES)

install: all $(ROOTDIR) $(ROOTBIN)

$(ROOTDIR):
	-$(INS.dir)

clean clobber lint:
