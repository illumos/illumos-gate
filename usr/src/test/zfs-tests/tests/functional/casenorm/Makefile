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

ROOTOPTPKG=	$(ROOT)/opt/zfs-tests
ROOTTESTDIR=	$(ROOTOPTPKG)/tests/functional/casenorm

TESTS=		setup				\
		cleanup				\
		case_all_values			\
		norm_all_values			\
		sensitive_none_lookup		\
		sensitive_none_delete		\
		sensitive_formd_lookup		\
		sensitive_formd_delete		\
		insensitive_none_lookup		\
		insensitive_none_delete		\
		insensitive_formd_lookup	\
		insensitive_formd_delete	\
		mixed_none_lookup		\
		mixed_none_lookup_ci		\
		mixed_none_delete		\
		mixed_formd_lookup		\
		mixed_formd_lookup_ci		\
		mixed_formd_delete

FILES=		casenorm.cfg	\
		casenorm.kshlib

ROOTTESTS=	$(TESTS:%=$(ROOTTESTDIR)/%)
ROOTFILES=	$(FILES:%=$(ROOTTESTDIR)/%)
$(ROOTTESTS) :=	FILEMODE = 0555
$(ROOTFILES) :=	FILEMODE = 0444

all lint clean clobber:

install:	$(ROOTTESTS) $(ROOTFILES)

$(ROOTTESTS) $(ROOTFILES): $(ROOTTESTDIR)

$(ROOTTESTDIR):
		$(INS.dir)

$(ROOTTESTDIR)/%: %.ksh
		$(INS.rename)

$(ROOTTESTDIR)/%: %
		$(INS.file)
