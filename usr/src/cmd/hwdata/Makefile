#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
#

include ../Makefile.cmd

HWDATA =	pci.ids usb.ids
HWDATADIR =	$(ROOT)/usr/share/hwdata
ROOTHWDATA =	$(HWDATA:%=$(HWDATADIR)/%)

$(ROOTHWDATA) :=	FILEMODE = 444

CLOBBERFILES += THIRDPARTYLICENSE.pciids

all install: THIRDPARTYLICENSE.pciids

THIRDPARTYLICENSE.pciids: pci.ids THIRDPARTYLICENSE.pciids.tmpl
	$(RM) $@
	$(SED) -e '/^$$/,$$ d' < pci.ids > $@
	$(CAT) THIRDPARTYLICENSE.pciids.tmpl >> $@

install: $(ROOTHWDATA)

$(HWDATADIR)/%: %
	$(INS.file)

lint check clean clobber:

FRC:

include ../Makefile.targ
