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
# Copyright (c) 2018 Joyent, Inc.
#

include $(SRC)/Makefile.master
include $(SRC)/cmd/Makefile.cmd

#
# Force c99 for everything
#
CSTD=		$(CSTD_GNU99)

#
# Deal with odd lint bits.
#
LINTFLAGS +=	-xerroff=E_NAME_DEF_NOT_USED2

#
# Install related definitions
#
ROOTOPTPKG = 	$(ROOT)/opt/vndtest
ROOTBIN =	$(ROOTOPTPKG)/bin
ROOTTST	=	$(ROOTOPTPKG)/tst
ROOTTSTDIR =	$(ROOTTST)/$(TSTDIR)
ROOTTSTEXES =	$(EXETESTS:%=$(ROOTTSTDIR)/%)
ROOTTSTSH =	$(SHTESTS:%=$(ROOTTSTDIR)/%)
ROOTOUT =	$(OUTFILES:%=$(ROOTTSTDIR)/%)
ROOTTESTS = 	$(ROOTTSTEXES) $(ROOTTSTSH) $(ROOTOUT)
FILEMODE =	0555
LDLIBS =	$(LDLIBS.cmd)
LINTEXE =	$(EXETESTS:%.exe=%.exe.ln)
