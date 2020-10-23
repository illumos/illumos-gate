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
# Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
#
#	This makefile drives the production of all implementation architecture
#	dependent modules for the i86xpv architecture.
#

UTSBASE = ..

include Makefile.i86xpv

def		:=	TARGET= def
all		:=	TARGET= all
install		:=	TARGET= install
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber
modlist		:=	TARGET= modlist
modlist	modlist.intel :=	NO_STATE= -K $$MODSTATE$$$$
check		:=	TARGET= check

.KEEP_STATE:

.PARALLEL:	$(PARALLEL_KMODS) $(XMODS) modlist modlist.intel

INITIAL_TARGETS = \
	genassym \
	unix \
	cpu/scripts

def all clean clobber: setup genassym unix .WAIT \
	$(KMODS) $(XMODS)

install: install_platforms setup genassym unix .WAIT \
	$(KMODS) $(XMODS)

clean:

# list the modules under i86xpv.
modlist: unix $(KMODS) $(XMODS)

# list the modules for Install -k i86xpv.
modlist.karch: modlist modlist.intel

modlist.intel:
	@cd $(SRC)/uts/intel; pwd; $(MAKE) $(NO_STATE) modlist

genassym unix $(KMODS):	FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

setup: FRC
	@cd cpu/scripts; pwd; $(MAKE) $(TARGET)

$(XMODS):	FRC
	@if [ -f $@/Makefile  ]; then \
		cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET); \
	else \
		true; \
	fi

install_h check:	FRC
	@cd sys; pwd; $(MAKE) $(TARGET)

#
# Definitions for the /platform directory aliases.
# Currently none for i86xpv.
#
PLAT_LINKS	=

#
# Make the /platform directories.  This is hardwired here because
# the first stage of the project (KBI) only implements the userland
# changes, but the only reasonable place to record the aliases is
# here in kernel land.
#
install_platforms:	$(ROOT_PSM_DIR) $(USR_PSM_DIR) \
			$(ROOT_PLAT_LINKS) $(USR_PLAT_LINKS) \
			$(OEM_USR_PLAT_LINKS)

FRC:

include ../Makefile.targ

#
# Cross-reference customization: build a cross-reference over all of the
# i86pc-related directories.
#
XRDIRS	= ../i86xpv ../i86pc ../intel ../common
XRPRUNE	= sun4v sun4u sun4 sfmmu sparc

cscope.out tags: FRC
	$(XREF) -x $@
