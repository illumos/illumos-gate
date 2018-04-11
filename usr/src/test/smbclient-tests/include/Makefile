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
# Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
#

include		$(SRC)/Makefile.master
include		../Makefile.com

INCS=	\
		default_cfg.ksh		\
		libtest.ksh		\
		services_common.ksh	\
		smbmount_common.ksh	\
		smbutil_common.ksh	\
		utils_common.ksh	\
		xattr_common.ksh

ROOTINCS=	$(INCS:%=$(ROOTINCDIR)/%)
$(ROOTINCS) :=	FILEMODE = 0444

all lint clean clobber:

install:	$(ROOTINCS)

$(ROOTINCS):	$(ROOTINCDIR)

$(ROOTINCDIR):
		$(INS.dir)

$(ROOTINCDIR)/%: %
		$(INS.file)
