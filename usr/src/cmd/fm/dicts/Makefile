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
# Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
#

include ../../Makefile.cmd

common_DCNAMES = \
	DISK \
	FMD \
	FMNOTIFY \
	NXGE \
	SMF \
	SUNOS \
	PCI \
	PCIEX \
	ZFS \
	SCA500 \
	SCA1000 \
	SENSOR \
	STORAGE \
	TEST \
	NIC

i386_DCNAMES = \
	AMD \
	INTEL \
	GMCA

sparc_DCNAMES = \
	SCF \
	SUN4 \
	SUN4U \
	SUN4V

DCNAMES = \
	$(common_DCNAMES) \
	$($(MACH)_DCNAMES)

ALLDCNAMES = \
	$(common_DCNAMES) \
	$(sparc_DCNAMES) \
	$(i386_DCNAMES)

DCFILES = $(DCNAMES:%=%.dict)
POFILES = $(DCNAMES:%=%.po)
MOFILES = $(DCNAMES:%=%.mo)

ROOTDCDIR = $(ROOTLIB)/fm/dict
ROOTLCDIR = $(ROOTLIB)/locale/C/LC_MESSAGES

ROOTDCFILES = $(DCNAMES:%=$(ROOTDCDIR)/%.dict)
ROOTPOFILES = $(DCNAMES:%=$(ROOTLCDIR)/%.po)
ROOTMOFILES = $(DCNAMES:%=$(ROOTLCDIR)/%.mo)
ROOTALLPOFILES = $(ALLDCNAMES:%=$(ROOTLCDIR)/%.po)

FILEMODE = 0444
$(ROOTALLPOFILES) := FILEMODE = 0644

DICTCK = ../scripts/dictck
DICTCKFLAGS = -b ../scripts/buildcode

all: $(MOFILES)

_msg: $(ROOTALLPOFILES)

$(ROOTDCDIR):
	$(INS.dir)

$(ROOTLIB)/locale:
	$(INS.dir)

$(ROOTLIB)/locale/C: $(ROOTLIB)/locale
	$(INS.dir)

$(ROOTLCDIR): $(ROOTLIB)/locale/C
	$(INS.dir)

$(ROOTDCDIR)/%: %
	$(INS.file)

$(ROOTLCDIR)/%: %
	$(INS.file)

%.mo: %.po
	$(MSGFMT) -o $@ $<

lint:
	@for name in $(DCNAMES); do\
		$(DICTCK) $(DICTCKFLAGS) $$name.dict $$name.po;\
	done

clean install_h lint:

clobber:
	$(RM) $(MOFILES)

install: all $(ROOTDCDIR) $(ROOTLCDIR) \
	$(ROOTDCFILES) $(ROOTALLPOFILES) $(ROOTMOFILES)
