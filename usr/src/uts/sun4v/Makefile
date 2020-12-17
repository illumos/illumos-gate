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
#
#	This makefile drives the production of all implementation architecture
#	dependent modules for the sun4v architecture.
#

UTSBASE = ..

include Makefile.sun4v
include Makefile.stpaul
include Makefile.huron
include Makefile.maramba
include Makefile.thunder
include Makefile.turgo
include Makefile.congo
include Makefile.monza

USR_GLENDALE_DIR	= $(USR_PLAT_DIR)/SUNW,Sun-Blade-T6320
USR_GLENDALE_SBIN_DIR	= $(USR_GLENDALE_DIR)/sbin
USR_GLENDALE_LIB_DIR	= $(USR_GLENDALE_DIR)/lib

def		:=	TARGET= def
all		:=	TARGET= all
install		:=	TARGET= install
install_h	:=	TARGET= install_h
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber
modlist		:=	TARGET= modlist
modlist	modlist.sparc :=	NO_STATE= -K $$MODSTATE$$$$
check		:=	TARGET= check

.KEEP_STATE:

.PARALLEL:	$(PARALLEL_KMODS) $(CLOSED_KMODS) $(XMODS) $(CLOSED_XMODS) \
		modlist modlist.sparc

# Override for CPU_KMODS... they cannot be built
# in parallel
.NO_PARALLEL:	$(CPU_KMODS)

def all clean clobber: genassym unix .WAIT \
	$(KMODS) $(CLOSED_KMODS) $(XMODS) $(CLOSED_XMODS) $(IMPLEMENTATIONS)

# list the modules under sun4v.
modlist: unix $(KMODS) $(CLOSED_KMODS) $(XMODS) $(CLOSED_XMODS) \
	$(IMPLEMENTATIONS)

# list the modules for Install -k sun4v.
modlist.karch: modlist modlist.sparc

modlist.sparc:
	@cd $(SRC)/uts/sparc; pwd; $(MAKE) $(NO_STATE) modlist

install: install_platforms genassym unix .WAIT $(KMODS) $(CLOSED_KMODS) \
	$(XMODS) $(CLOSED_XMODS) $(IMPLEMENTATIONS)

genassym unix $(KMODS):	FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

$(IMPLEMENTATIONS):	FRC
	@cd $@; pwd; THISIMPL=$@ $(MAKE) $(NO_STATE) $(TARGET)

$(XMODS):	FRC
	@if [ -f $@/Makefile  ]; then \
		cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET); \
	else \
		true; \
	fi

$(CLOSED_XMODS):	FRC
	@if [ -f $(CLOSED)/uts/sun4v/$@/Makefile  ]; then \
		cd $(CLOSED)/uts/sun4v/$@; pwd; \
		    $(MAKE) $(NO_STATE) $(TARGET); \
	else \
		true; \
	fi

$(CLOSED_KMODS):	FRC
	cd $(CLOSED)/uts/sun4v/$@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

install_h check:	install_platforms $(IMPLEMENTATIONS) FRC
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

$(LINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%): $(ROOT_PLAT_DIR)
	$(INS.slink1)

#
# create directories in /usr/platform/ for the implementations that are
# defined in $(IMPLEMENTED_PLATFORM)
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
			$(LINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%) \
			$(USR_DESKTOP_DIR) $(USR_DESKTOP_INC_DIR) \
			$(USR_DESKTOP_SBIN_DIR) $(USR_DESKTOP_LIB_DIR) \
			$(USR_STPAUL_DIR) $(USR_STPAUL_SBIN_DIR) \
			$(USR_STPAUL_LIB_DIR) \
			$(USR_GLENDALE_DIR) $(USR_GLENDALE_SBIN_DIR) \
			$(USR_GLENDALE_LIB_DIR) \
			$(USR_HURON_DIR) \
			$(USR_HURON_SBIN_DIR) $(USR_HURON_LIB_DIR) \
			$(USR_MARAMBA_DIR) $(USR_MARAMBA_SBIN_DIR) \
			$(USR_MARAMBA_LIB_DIR) \
			$(USR_THUNDER_DIR) $(USR_THUNDER_SBIN_DIR) \
			$(USR_THUNDER_LIB_DIR) \
			$(USR_TURGO_DIR) $(USR_TURGO_SBIN_DIR) \
			$(USR_TURGO_LIB_DIR) \
			$(USR_CONGO_DIR) $(USR_CONGO_SBIN_DIR) \
			$(USR_CONGO_LIB_DIR) \
			$(USR_MONZA_DIR) \
			$(USR_MONZA_SBIN_DIR) $(USR_MONZA_SBIN_LINKS)


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

$(USR_STPAUL_DIR):		$(USR_SUN4V_PLAT_DIR)
	-$(INS.dir)

$(USR_STPAUL_SBIN_DIR):		$(USR_STPAUL_DIR)
	$(INS.slink5)

$(USR_STPAUL_LIB_DIR):		$(USR_STPAUL_DIR)
	-$(INS.dir)

$(USR_HURON_DIR):		$(USR_SUN4V_PLAT_DIR)
	-$(INS.dir)

$(USR_HURON_SBIN_DIR):		$(USR_HURON_DIR)
	$(INS.slink5)

$(USR_HURON_LIB_DIR):		$(USR_HURON_DIR)
	-$(INS.dir)

$(USR_GLENDALE_DIR):		$(USR_SUN4V_PLAT_DIR)
	-$(INS.dir)

$(USR_GLENDALE_SBIN_DIR):		$(USR_GLENDALE_DIR)
	$(INS.slink5)

$(USR_GLENDALE_LIB_DIR):		$(USR_GLENDALE_DIR)
	-$(INS.dir)

$(USR_MARAMBA_DIR):		$(USR_SUN4V_PLAT_DIR)
	-$(INS.dir)

$(USR_MARAMBA_SBIN_DIR):	$(USR_MARAMBA_DIR)
	$(INS.slink5)

$(USR_MARAMBA_LIB_DIR):		$(USR_MARAMBA_DIR)
	-$(INS.dir)

$(USR_THUNDER_DIR):		$(USR_SUN4V_PLAT_DIR)
	-$(INS.dir)

$(USR_THUNDER_SBIN_DIR):	$(USR_THUNDER_DIR)
	$(INS.slink5)

$(USR_THUNDER_LIB_DIR):		$(USR_THUNDER_DIR)
	-$(INS.dir)

$(USR_TURGO_DIR):		$(USR_SUN4V_PLAT_DIR)
	-$(INS.dir)

$(USR_TURGO_SBIN_DIR):		$(USR_TURGO_DIR)
	$(INS.slink5)

$(USR_TURGO_LIB_DIR):		$(USR_TURGO_DIR)
	-$(INS.dir)

$(USR_CONGO_DIR):		$(USR_SUN4V_PLAT_DIR)
	-$(INS.dir)

$(USR_CONGO_SBIN_DIR):		$(USR_CONGO_DIR)
	$(INS.slink5)

$(USR_CONGO_LIB_DIR):		$(USR_CONGO_DIR)
	-$(INS.dir)

$(USR_MONZA_DIR):		$(USR_SUN4V_PLAT_DIR)
	-$(INS.dir)

$(USR_MONZA_SBIN_DIR):		$(USR_MONZA_DIR)
	-$(INS.dir)

$(USR_MONZA_SBIN_LINKS):	$(USR_MONZA_SBIN_DIR)
	$(INS.slink7)

include ../Makefile.targ

#
# Cross-reference customization: build a cross-reference over all of the
# sun4v-related directories.
#
XRDIRS	= ../sun4v ../sun4 ../sfmmu ../sparc ../sun ../common
XRPRUNE = i86pc sun4u intel

cscope.out tags: FRC
	$(XREF) -x $@
