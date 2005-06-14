#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1996 by Sun Microsystems, Inc.
# All Rights Reserved.
#

FILES=ntp.client ntp.server

include ../../Makefile.cmd
include ../Makefile.cmd

CLOBBERFILES = $(ROOTETCINETFILES)
FILEMODE=644
OWNER=root
GROUP=sys
VARNTPD=$(ROOT)/var/ntp
VARNTPSTATSD=$(VARNTPD)/ntpstats
DIRS=$(VARNTPD) $(VARNTPSTATSD)
$(DIRS) :=	OWNER= root
$(DIRS) :=	GROUP= sys
$(DIRS) :=	DIRMODE=755

.KEEP_STATE:

all clean lint:

install: $(DIRS) $(ROOTETCINETFILES)

$(DIRS):
	$(INS.dir)

include ../../Makefile.targ
