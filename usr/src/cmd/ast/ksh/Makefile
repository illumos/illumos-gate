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
# Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
#

SHELL= /usr/bin/ksh93

PROG= ksh

USRKSH_ALIAS_LIST=ksh ksh93 rksh rksh93

include ../../Makefile.cmd

SUBDIRS= $(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

SUBDIRS += builtins

ARCH32_i386= i86
ARCH32_sparc= sparcv7
ARCH32= $(ARCH32_$(MACH))

all		:=	TARGET = all
install		:=	TARGET = install
clean		:=	TARGET = clean
clobber		:=	TARGET = clobber
lint		:=	TARGET = lint
testshell	:=	TARGET = testshell

.KEEP_STATE:
# Serialise the build to avoid running the test suite for 32-bit
# and 64-bit in parallel
.NO_PARALLEL: $(SUBDIRS)

all clean clobber lint testshell: $(SUBDIRS)
install_h _feature:

# dummy file since AST/ksh doesn't use *.po files
# (and "ksh" is just a frontend which calls directly into libshell,
# i.e. there are no l10n strings here)
$(PROG).po:
	$(RM) ksh.po ksh93.po ; \
	$(TOUCH) $(PROG).po

install: $(SUBDIRS)
	@(set -o xtrace ; \
	builtin ln ; \
	builtin rm ; \
	for i in $(USRKSH_ALIAS_LIST) ; do \
		[[ "$$i" == "$(PROG)" ]] && continue ; \
		rm -f "$(ROOTBIN)/$$i" ; \
		ln "$(ROOTBIN)/$(PROG)" "$(ROOTBIN)/$$i" ; \
	done \
	)
	$(RM) $(ROOTSBIN)/sh
	$(SYMLINK) ../usr/bin/$(ARCH32)/ksh93 $(ROOTSBIN)/sh
	$(RM) $(ROOTSBIN)/jsh
	$(SYMLINK) ../usr/bin/ksh93 $(ROOTSBIN)/jsh
	$(RM) $(ROOTBIN)/jsh
	$(SYMLINK) ksh93 $(ROOTBIN)/jsh
	$(RM) $(ROOTBIN)/sh
	$(SYMLINK) $(ARCH32)/ksh93 $(ROOTBIN)/sh
	$(RM) $(ROOTLIB)/rsh
	$(SYMLINK) ../bin/ksh93 $(ROOTLIB)/rsh

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)
FRC:

include ../../Makefile.targ
