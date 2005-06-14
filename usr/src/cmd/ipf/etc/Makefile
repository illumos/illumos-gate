#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
#cmd/ipf/etc/Makefile
#

PFILAP=		pfil.ap
IPFCONF=	ipf.conf
IPFPROG=	$(PFILAP) $(IPFCONF)

include ../../Makefile.cmd


ETCIPF= $(ROOTETC)/ipf

DIRS=  $(ETCIPF)

ETCIPFPROG=	$(IPFPROG:%=$(ETCIPF)/%)

$(ETCIPFPROG):=	FILEMODE= 0644
OWNER= root
GROUP= sys

.KEEP_STATE:

all: $(IPFPROG) $(DIRS) $(ETCIPFPROG)

install: all $(DIRS)

$(PFILAP):
	$(SH) $@.sh

$(ETCIPF)/% : % $(ETCIPF)
	$(INS.file)

$(DIRS):
	$(INS.dir)

clean:

clobber:

lint:

.PARALLEL:
