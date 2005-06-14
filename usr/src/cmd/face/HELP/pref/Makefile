#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1990 by Sun Microsystems, Inc.
#
# cmd/face/HELP/pref/Makefile

include		../../../Makefile.cmd
include		../../src/Makefile.com

# HELP bin install

ROOTDIR=	$(ROOTVMSYS)/HELP/pref

HELPFILES=	T.hcolor1 T.hcolor10 T.hcolor2 T.hcolor3 T.hcolor4 T.hcolor5 \
		T.hcolor6 T.hcolor7 T.hcolor8 T.hcolor9 T.hdisp1 T.hdisp2 \
		T.hdisp3 T.hdisp4 T.hfunc1 T.hfunc2 T.hfunc3 T.hfunc4 T.hfunc5 \
		T.hfunc6 T.hfunc7 T.hpref

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
