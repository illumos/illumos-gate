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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright 2015 Igor Kozhukhov <ikozhukhov@gmail.com>
#
#	This makefile drives the production of all implementation architecture
#	dependent modules for the sun4u architecture.
#

UTSBASE = ..

include Makefile.sun4u

def		:=	TARGET= def
def.prereq	:=	TARGET= def
all		:=	TARGET= all
all.prereq	:=	TARGET= all
install		:=	TARGET= install
install.prereq	:=	TARGET= install
install_h	:=	TARGET= install_h
install_h.prere	:=	TARGET= install_h
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber
modlist		:=	TARGET= modlist
modlist	modlist.sparc :=	NO_STATE= -K $$MODSTATE$$$$
check		:=	TARGET= check

.KEEP_STATE:

.PARALLEL:	$(PARALLEL_KMODS) $(XMODS) \
		$(IMPLEMENTATIONS) \
		modlist modlist.sparc

# Override for CPU_KMODS... they cannot be built
# in parallel
.NO_PARALLEL:	$(CPU_KMODS)

def all clean clobber: genassym unix .WAIT \
	$(KMODS) $(XMODS) $(IMPLEMENTATIONS)

clobber: clobber.targ

# list the modules under sun4u.
modlist: unix $(KMODS) $(XMODS) $(IMPLEMENTATIONS:.WAIT=)

# list the modules for Install -k sun4u.
modlist.karch: modlist modlist.sparc

modlist.sparc:
	@cd $(SRC)/uts/sparc; pwd; $(MAKE) $(NO_STATE) modlist

install: install_platforms genassym unix .WAIT $(KMODS) \
	$(XMODS) $(IMPLEMENTATIONS)

genassym unix $(KMODS):	FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

#
# Privilege constants
#
# NOTE: The rules for generating priv_const.c file are shared between all
# processor architectures and should be kept in sync. If they are changed in
# this file make sure that x86 rules are updated as well.
#
PRIVS_C = $(UTSBASE)/common/os/priv_const.c

$(PRIVS_C): $(PRIVS_AWK) $(PRIVS_DEF)
	$(AWK) -f $(PRIVS_AWK) < $(PRIVS_DEF) cfile=$@

CLOBBERFILES += $(PRIVS_C)

#
# Prerequisites
#
# The uts/Makefile defines build parallelism for sun4 platforms such that sparc,
# sun4u and sun4v are all built in parallel. Also this Makefile specifies that
# all IMPLEMENTATIONS sun4u sub-platforms are built in parallel. This requires
# building certain parts before the parallel build can start. The uts/Makefile
# appends the '.prereq' string to the original target and executes this Makefile
# to build any prerequisites needed before the full parallel build can start.
# After that make continues with normal targets.
#
# Any build prerequisites for sun4 and IMPLEMENTATIONS builds should be
# described here.
#
# genassym is used to build dtrace and genunix, so it should be built first.
#
# priv_const.c is required to build genunix.
#
# genunix is used by everyone to ctfmerge with. Genunix is merged with sparc/ip
#   so as a side effect this dependency builds sparc/ip as part of the
#   prerequisites.
#
# unix is not required by itself but several sun4u platforms require
#   sun4u/platmod to be present. The easiest way to achieve this is to build
#   sun4u/unix first since sun4u/unix Makefile builds sun4u/platform correctly.
#   This causes full sun4u/unix to be built before all sun4u platforms and
#   before uts/sun4v and uts/sparc, but it acceptable since it is not spending
#   too much time building sun4u/unix.
#
all.prereq def.prereq install.prereq: genassym genunix unix

#
# Various sun4u platforms expect proto/root_sparc/platform/sun4u/include to be
# present. This is handled by running make install_h in sun4u/unix directory
# first.
#
install_h.prereq: FRC
	@cd sys; pwd; $(MAKE) $(TARGET)

#
# Nothing to do with any other prerequisites
#
%.prereq:

#
# Platform inter-dependencies
#
lw8: serengeti

quasar: darwin

#
# The genunix requires priv_const.c file to be generated first.
#
genunix: $(PRIVS_C)

#
# Rules
#

$(IMPLEMENTATIONS):	FRC
	@cd $@; pwd; THISIMPL=$@ $(MAKE) $(NO_STATE) $(TARGET)

$(XMODS):	FRC
	@if [ -f $@/Makefile  ]; then \
		cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET); \
	else \
		true; \
	fi

install_h check: install_platforms $(IMPLEMENTATIONS)
	@cd sys; pwd; $(MAKE) $(TARGET)
	@cd vm; pwd; $(MAKE) $(TARGET)

#
# Rules for the /platforms directories.  This is hardwired here because
# the first stage of the project (KBI) only implements the userland
# changes, but the only reasonable place to record the aliases is
# here in kernel land.
#
$(ROOT_PLAT_DIRS): $(ROOT_PLAT_DIR)
	-$(INS.dir)

#
# create directories in /usr/platform/ for the implementations that are
# defined in $(IMPLEMENTED_PLATFORM)
#       (eg. SUNW,Ultra-1)
#
# Foreach $(IMPLEMENTED_PLATFORM) there can be a list of $(LINKED_PLATFORMS)
# that are linked to it.
#
$(USR_PLAT_DIR)/$(IMPLEMENTED_PLATFORM):	$(USR_PLAT_DIR)
	-$(INS.dir)

#
# create the links in /usr/platform/ foreach $(LINKED_PLATFORMS)
# to it's corresponding $(IMPLEMENTED_PLATFORM).
#
PLATFORMS	= $(LINKED_PLATFORMS)

$(USR_PLAT_DIRS): $(USR_PLAT_DIR)
	$(INS.slink3)

PLATFORMS	+= $(IMPLEMENTED_PLATFORM)

#
# Make the /platforms directories.  This is hardwired here because
# the first stage of the project (KBI) only implements the userland
# changes, but the only reasonable place to record the aliases is
# here in kernel land.
#
install_platforms:	$(ROOT_PSM_DIR) $(USR_PSM_DIR) \
			$(ROOT_PLAT_DIRS) $(USR_PLAT_DIRS) \
			$(USR_DESKTOP_DIR) $(USR_DESKTOP_INC_DIR) \
			$(USR_DESKTOP_SBIN_DIR) $(USR_DESKTOP_LIB_DIR)

#
# rules for making include, sbin, lib dirs/links in
# /usr/platform/$(PLATFORM)/ for desktop platforms
#
$(USR_DESKTOP_INC_DIR):		$(USR_DESKTOP_DIR)
	$(INS.slink4)

$(USR_DESKTOP_SBIN_DIR):	$(USR_DESKTOP_DIR)
	$(INS.slink5)

$(USR_DESKTOP_LIB_DIR):		$(USR_DESKTOP_DIR)
	-$(INS.dir)

include ../Makefile.targ

#
# Cross-reference customization: build a cross-reference over all of the
# sun4u-related directories.
#
XRDIRS	= ../sun4u ../sun4 ../sfmmu ../sparc ../sun ../common
XRPRUNE = i86pc

cscope.out tags: FRC
	$(XREF) -x $@
