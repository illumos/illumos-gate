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
# Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
#

include ../Makefile.cmd

SUBDIRS1 = \
	cryptoadm \
	decrypt \
	digest \
	elfsign \
	kmfcfg \
	pktool \
	tpmadm

SUBDIRS2 = \
	etc \
	scripts

all:=           TARGET= all
install:=       TARGET= install
clean:=         TARGET= clean
clobber:=       TARGET= clobber
lint:=          TARGET= lint
_msg:=          TARGET= _msg

.KEEP_STATE:

all clean clobber lint _msg: $(SUBDIRS1) $($(MACH)_SUBDIRS)

install: $(SUBDIRS1) $(SUBDIRS2) $($(MACH)_SUBDIRS)

$(SUBDIRS1) $(SUBDIRS2) $($(MACH)_SUBDIRS) : FRC
	@cd $@; pwd; $(MAKE) $(MFLAGS) $(TARGET)

FRC:
