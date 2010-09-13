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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include ../../Makefile.master

# note: the x86 needs the "bootblks" target for installboot
SUBDIRS= lib bootblks boot cpr bootlst

all		:=	TARGET= all
install		:=	TARGET= install
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber
lint		:=	TARGET= lint
clean.lint	:=	TARGET= clean.lint

.KEEP_STATE:

all install clean lint clean.lint clobber: $(SUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

#
# Cross-reference customization: include all of the PROM and standalone
# goo in the cross-reference, except for the crufty "old" directory.
#
STANDDIR=	../../stand
PROMDIRS=	../promif ../../uts/intel/ia32/promif ../../uts/intel/promif
XRDIRS +=	$(STANDDIR)/lib $(STANDDIR)/sys $(PROMDIRS)
XRPRUNE =	old
