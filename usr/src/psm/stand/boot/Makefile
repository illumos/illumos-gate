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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include		../../../Makefile.master

sparcv9_ARCHITECTURES = sparcv9
sparc_ARCHITECTURES = $(sparcv9_ARCHITECTURES)

SUBDIRS = $($(MACH)_ARCHITECTURES)

all		:=	TARGET= all
install		:=	TARGET= install
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber
lint		:=	TARGET= lint

.KEEP_STATE:

all install lint clean: $(SUBDIRS)

clobber: $(SUBDIRS)
	$(RM) make.out lint.out

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

#
# Cross-reference customization: include all boot-related source files.
#
UTSDIR =	../../../uts
UTSCLOSED =	../../../../closed/uts
STANDLIBDIR =	../../../stand/lib
STANDSYSDIRS =	../../../stand/sys
PROMDIRS =	../../promif
NAMESDIRS =	../lib/names
XRDIRS += 	$(STANDLIBDIR) $(STANDSYSDIRS) $(PROMDIRS) $(NAMESDIRS)

#
# Components beginning with B! are in the open and closed trees; those
# beginning with O! are just in the open tree.
#
XRINCCOMP = B!sun4u O!sfmmu O!sparc/v7 O!sparc/v9 B!sparc B!sun B!common
XRINC_TMP = $(XRINCCOMP:B!%=$(UTSDIR)/%)
XRINCDIRS = $(XRINC_TMP:O!%=$(UTSDIR)/%)
$(CLOSED_BUILD)XRINC_TMP = $(XRINCCOMP:B!%=$(UTSDIR)/% $(UTSCLOSED)/%)
$(CLOSED_BUILD)XRINCDIRS = $(XRINC_TMP:O!%=$(UTSDIR)/%)

cscope.out tags: FRC
	$(XREF) -x $@

FRC:
