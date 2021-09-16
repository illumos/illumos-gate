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
# Copyright 2019 Joyent, Inc.
#

include $(SRC)/Makefile.master
include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.cmd.64

#
# Force c99 for everything
#
CSTD=		$(CSTD_GNU99)

CFLAGS +=	$(CCVERBOSE) -_gcc=-Wimplicit-function-declaration \
		-_gcc=-Wno-parentheses
CFLAGS64 +=	$(CCVERBOSE) -_gcc=-Wimplicit-function-declaration \
		-_gcc=-Wno-parentheses
CPPFLAGS =	-I$(SRC)/cmd/bhyve \
		-I$(COMPAT)/bhyve -I$(CONTRIB)/bhyve \
		-I$(CONTRIB)/bhyve/dev/usb/controller \
		-I$(CONTRIB)/bhyve/dev/mii \
		$(CPPFLAGS.master) \
		-I$(SRC)/uts/i86pc/io/vmm \
		-I$(SRC)/uts/common \
		-I$(SRC)/uts/i86pc \
		-I$(SRC)/lib/libdladm/common \
		-DWITHOUT_CAPSICUM
CPPFLAGS +=	-I$(COMPAT)/bhyve/amd64 -I$(CONTRIB)/bhyve/amd64
LDFLAGS +=	-lproc

SMOFF += all_func_returns

CLEANFILES +=	$(EXETESTS)
CLOBBERFILES +=	$(ROOTTESTS)

#
# Install related definitions
#
ROOTOPTPKG =	$(ROOT)/opt/bhyvetest
ROOTBIN =	$(ROOTOPTPKG)/bin
ROOTTST =	$(ROOTOPTPKG)/tst
ROOTTSTDIR =	$(ROOTTST)/$(TSTDIR)
ROOTTSTEXES =	$(EXETESTS:%=$(ROOTTSTDIR)/%)
ROOTTSTSH =	$(SHTESTS:%=$(ROOTTSTDIR)/%)
ROOTOUT =	$(OUTFILES:%=$(ROOTTSTDIR)/%)
ROOTTESTS =	$(ROOTTSTEXES) $(ROOTTSTSH) $(ROOTOUT)
FILEMODE =	0555
LDLIBS =	$(LDLIBS.cmd)
