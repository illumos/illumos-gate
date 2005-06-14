#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

MANIFEST=	ipfilter.xml pfil.xml 
SVCMETHOD=	ipfilter pfil

include $(SRC)/cmd/Makefile.cmd

ROOTMANIFESTDIR=	$(ROOTSVCNETWORK)
$(ROOTMANIFEST)		:= FILEMODE= 444

include $(SRC)/cmd/Makefile.targ

$(ROOTMANIFESTDIR)/%: %
		$(INS.file)

clean:
		$(RM) $(OBJS)

lint:		$(SRCS) lint_SRCS

install:	$(ROOTMANIFEST) $(ROOTSVCMETHOD)

check:		$(CHKMANIFEST)
