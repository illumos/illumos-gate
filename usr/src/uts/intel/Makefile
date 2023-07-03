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
# uts/intel/Makefile
#
# Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2015 Igor Kozhukhov <ikozhukhov@gmail.com>
#
#	This makefile drives the production of all implementation architecture
#	independent modules for Intel processors.

UTSBASE = ..

include Makefile.intel

# Unset BINARY for clobber.targ because otherwise it will try to remove
# a directory under uts/intel.
BINARY=

#
# dprov is delivered in the SUNWcryptoint package.
#
DRV_KMODS	+= dprov

#
#
def		:=	TARGET= def
def.prereq	:=	TARGET= def
all		:=	TARGET= all
all.prereq	:=	TARGET= all
install		:=	TARGET= install
install.prereq	:=	TARGET= install
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber
check		:=	TARGET= check
install_h	:=	TARGET= install_h
install_h.prereq	:=	TARGET= install_h

.KEEP_STATE:

.PARALLEL:	$(PARALLEL_KMODS) $(XMODS) config

def all install clean clobber: $(KMODS) $(XMODS) config

clobber: clobber.targ

#
# Privilege constants
#
# NOTE: The rules for generating priv_const.c file are shared between all
# processor architectures and and should be kept in sync. If they are changed in
# this file make sure that sparc rules are updated as well.
#
PRIVS_C = $(SRC)/uts/common/os/priv_const.c

$(PRIVS_C): $(PRIVS_AWK) $(PRIVS_DEF)
	$(AWK) -f $(PRIVS_AWK) < $(PRIVS_DEF) cfile=$@

CLOBBERFILES += $(PRIVS_C)

#
# Prerequisites
#
# The uts/Makefile defines build parallelism for x86 platforms such that i86pc,
# i86xpv and intel are all built in parallel. This requires building certain
# parts before the parallel build can start. The uts/Makefile appends the
# '.prereq' string to the original target and executes this Makefile to build
# any prerequisites needed before the full parallel build can start. After that
# make continues with normal targets.
#
# Any build prerequisites for x86 builds should be described here.
#
# genassym is used to build intel/dtrace and genunix, so it should be built
# first.
#
# priv_const.c is required to build genunix.
#
# genunix is used by everyone to ctf-merge with. Genunix is CTF-merged with
#   intel/ip so as a side effect this dependency builds intel/ip as part of the
#   prerequisites.
#
# intel/dtrace depends on i86pc/genassym, so we need to build both
# i86pc/genassym and intel/genassym.
#
all.prereq install.prereq def.prereq: genunix FRC
	@cd ../i86pc/genassym; pwd; $(MAKE) $(@:%.prereq=%)

#
# Nothing to do for any other prerequisite targets.
#
%.prereq:

genunix: $(PRIVS_C)

$(KMODS) $(SUBDIRS) config:	FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

$(XMODS):	FRC
	cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

install_h check:	FRC
	@cd sys; pwd; $(MAKE) $(TARGET)
	@cd asm; pwd; $(MAKE) $(TARGET)
	@cd ia32/sys; pwd; $(MAKE) $(TARGET)
	@cd amd64/sys; pwd; $(MAKE) $(TARGET)

include ../Makefile.targ
