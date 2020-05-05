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
# Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
#
# KMF Prototype Makefile
#
include	../Makefile.lib

LIBRARY=	libkmf.a
VERS=		1

SUBDIRS	=	ber_der libkmf plugins mappers

HDRS=	kmfapi.h kmftypes.h
HDRDIR= include

all :=          TARGET= all
clean :=        TARGET= clean
clobber :=      TARGET= clobber
install :=      TARGET= install
install_h :=    TARGET= install_h

all install: install_h $(SUBDIRS) THIRDPARTYLICENSE

clean clobber:	$(SUBDIRS)

install_h:	$(ROOTHDRDIR) $(ROOTHDRS)

check: $(CHECKHDRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

THIRDPARTYLICENSE: cdsa_license.txt
	$(SED) -n '/Intel Open Source/,$$p' cdsa_license.txt > $@

CLOBBERFILES += THIRDPARTYLICENSE

include $(SRC)/lib/Makefile.targ
