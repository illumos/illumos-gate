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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

SHELL=/usr/bin/ksh

include ../../Makefile.ksh93switch

$(BINKSH_IS_KSH93)PROG= ksh
$(BINKSH_IS_KSH93)USRKSH_ALIAS_LIST=ksh ksh93 rksh rksh93 pfksh

$(BINKSH_ISNOT_KSH93)PROG= ksh93
$(BINKSH_ISNOT_KSH93)USRKSH_ALIAS_LIST=ksh93 rksh93

include ../Makefile.cmd

SUBDIRS= $(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

# Serialise the build to avoid that we run the test suite for 32bit
# and 64bit in parallel
.NO_PARALLEL: $(SUBDIRS)

all		:=	TARGET = all
install		:=	TARGET = install
clean		:=	TARGET = clean
clobber 	:=	TARGET = clobber
lint		:=	TARGET = lint
testshell	:=	TARGET = testshell

.KEEP_STATE:

all clean clobber lint testshell: $(SUBDIRS)

# dummy file since AST/ksh doesn't use *.po files
# (and "ksh" is just a frontend which calls directly into libshell,
# e.g. there are no l10n strings here)
$(PROG).po:
	$(RM) ksh.po ksh93.po
	touch $(PROG).po

install:	$(ISAEXEC) $(SUBDIRS)
	$(RM) $(ROOTPROG)
	$(LN) $(ISAEXEC) $(ROOTPROG)
	@(set -o xtrace ; \
	for i in $(USRKSH_ALIAS_LIST) ; do \
		[[ "$$i" = "$(PROG)" ]] && continue ; \
		$(RM) "$(ROOTBIN)/$$i" ; \
		$(LN) "$(ROOTBIN)/$(PROG)" "$(ROOTBIN)/$$i" ; \
	done \
	)

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include ../Makefile.targ
