#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1990 by Sun Microsystems, Inc.
#
# cmd/face/programs/Makefile

include		../../../Makefile.cmd
include		../../src/Makefile.com

ROOTDIR=	$(ROOTVMSYS)/HELP/programs

HELPFILES=	T.hadd1 T.hadd2 T.hadd3 T.hadd4 T.hadd5 T.hmod1 T.hmod2 \
		T.hmod3 T.hmod4 T.hmod5 T.list1 T.list2 T.list3 T.sadm

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
