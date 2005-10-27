#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1990 by Sun Microsystems, Inc.
#
# cmd/face/HELP/spell/Makefile

include		../../../Makefile.cmd
include		../../src/Makefile.com

ROOTDIR=	$(ROOTVMSYS)/HELP/spell

HELPFILES=	T.hspell1

ROOTBIN=	$(HELPFILES:%=$(ROOTDIR)/%)

# install rules

$(ROOTDIR)/% : %
	$(INS.file)

.KEEP_STATE:

all: $(HELPFILES)

install: all $(ROOTDIR) $(ROOTBIN)

$(ROOTDIR):
	-$(INS.dir)

clean clobber lint:
