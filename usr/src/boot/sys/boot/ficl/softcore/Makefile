#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2018 Toomas Soome <tsoome@me.com>
#

include $(SRC)/Makefile.master

install all: softcore.c

SOFTCORE=	$(SRC)/common/ficl/softcore
PROG=		$(ONBLD_TOOLS)/bin/$(MACH)/makesoftcore

#
# not needed: file access
#
FR = softcore.fr ifbrack.fr prefix.fr ficl.fr jhlocal.fr marker.fr
FR += freebsd.fr ficllocal.fr oo.fr classes.fr string.fr wordsets.fr
SOURCES=	$(FR:%=$(SOFTCORE)/%)

softcore.c: $(SOURCES)
	$(PROG) $(SOURCES)

clobber clean:
	$(RM) softcore.c
