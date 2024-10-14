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
# Copyright 2022 Oxide Computer Company
#

include $(SRC)/Makefile.master
include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.cmd.64

#
# Force c99 for everything
#
CSTD=		$(CSTD_GNU99)

CPPFLAGS =	-I$(COMPAT)/bhyve -I$(CONTRIB)/bhyve \
		-I$(COMPAT)/bhyve/amd64 -I$(CONTRIB)/bhyve/amd64 \
		$(CPPFLAGS.master) \
		-I$(SRC)/cmd/bhyve/common \
		-DWITHOUT_CAPSICUM

SMOFF += all_func_returns

CLOBBERFILES +=	$(PROG)

#
# Install related definitions
#
ROOTOPTPKG =	$(ROOT)/opt/bhyve-tests
ROOTTESTS =	$(ROOTOPTPKG)/tests
TESTDIR =	$(ROOTTESTS)/$(TESTSUBDIR)

FILEMODE =	0555
LDLIBS =	$(LDLIBS.cmd)
