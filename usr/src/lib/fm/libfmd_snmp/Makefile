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
# Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
#
#

include ../../Makefile.lib
include ../Makefile.lib

FMHDRS = fmd_snmp.h
HDRDIR = common

SUBDIRS = $(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

MIBFILES = SUN-FM-MIB.mib SUN-IREPORT-MIB.mib

ROOTNETSNMPMIBDIR = $(ROOT)/etc/net-snmp/snmp/mibs
ROOTMIBS = $(MIBFILES:%=$(ROOTNETSNMPMIBDIR)/%)

$(ROOTMIBS) := FILEMODE = 0644
$(ROOTNETSNMPMIBDIR) := DIRMODE = 0755

all := TARGET = all
clean := TARGET = clean
clobber := TARGET = clobber
install := TARGET = install

.KEEP_STATE:

all clean clobber: $(SUBDIRS)

install: install_h install_mibs .WAIT $(SUBDIRS)

install_h: $(ROOTFMHDRS)

install_mibs: $(ROOTNETSNMPMIBDIR) $(ROOTMIBS)

check: $(CHECKHDRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

$(ROOTNETSNMPMIBDIR):
	$(INS.dir)

$(ROOTNETSNMPMIBDIR)/%: mibs/%
	$(INS.file)

FRC:

include ../../Makefile.targ
include ../Makefile.targ
