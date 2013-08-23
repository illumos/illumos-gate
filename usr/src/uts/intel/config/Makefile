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
# uts/intel/config/Makefile
# Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#	This makefile drives the production of the kernel configuration files.
#
#	intel architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
#	Define the module and object file sets.
#
SRCDIR		= $(UTSBASE)/intel/os
PATH2INST	= path_to_inst
CONFIGFILES	= name_to_major minor_perm driver_aliases name_to_sysnum \
		  driver_classes dacf.conf $(PATH2INST) mach
SECCONFIG	= device_policy priv_names
BOOTIMAGE	= splashimage.xpm
ALTBOOTIMAGE	= solaris.xpm	# Temporary, for compatibility
BOOTENVRC	= bootenv.rc
DEVMASTER	= master
FILEMODE	= 644
ROOTETC		= $(ROOT)/etc
ROOTETCSEC	= $(ROOTETC)/security
ROOTBOOT	= $(ROOT)/boot
BOOTSOLARIS	= $(ROOTBOOT)/solaris
BOOTDEVICEDB	= $(BOOTSOLARIS)/devicedb

SRCFILES	= $(CONFIGFILES:%=$(SRCDIR)/%) $(SECCONFIG:%=$(SRCDIR)/%)
SRCFILES	+= $(BOOTIMAGE:%=$(SRCDIR)/%)
SRCFILES	+= $(BOOTENVRC:%=$(SRCDIR)/%)
SRCFILES	+= $(DEVMASTER:%=$(SRCDIR)/%)
ROOTCONFIGFILES	= $(CONFIGFILES:%=$(ROOTETC)/%) $(SECCONFIG:%=$(ROOTETCSEC)/%)
ROOTCONFIGFILES	+= $(BOOTIMAGE:%=$(ROOTBOOT)/%)
ROOTCONFIGFILES	+= $(BOOTENVRC:%=$(BOOTSOLARIS)/%)
ROOTCONFIGFILES	+= $(DEVMASTER:%=$(BOOTDEVICEDB)/%)
ROOTALTBOOTIMAGE = $(ALTBOOTIMAGE:%=$(ROOTBOOT)/%)

#
#	Default build targets.
#
.KEEP_STATE:

def all: $(SRCFILES)

install: all $(ROOTCONFIGFILES) $(ROOTALTBOOTIMAGE)

#
#	The ROOTETC directory is made by ../../../Targetdirs
#	through the rootdirs target in ../../../Makefile.
#
#	etc/path_to_inst has permissions different from the other config files
#
$(ROOTETC)/$(PATH2INST):= FILEMODE=444

$(ROOTETC)/%: $(SRCDIR)/%
	$(INS.file)

$(ROOTETCSEC)/%: $(SRCDIR)/%
	$(INS.file)

$(ROOTBOOT):
	$(INS) -s -d -m $(DIRMODE) $@

$(ROOTBOOT)/%: $(ROOTBOOT) $(SRCDIR)/%
	$(INS.file)

$(ROOTBOOT)/solaris.xpm: $(ROOTBOOT)/splashimage.xpm
	$(RM) $@; $(LN) $(ROOTBOOT)/splashimage.xpm $@


$(BOOTSOLARIS):
	$(INS) -s -d -m $(DIRMODE) $@

$(BOOTSOLARIS)/%: $(BOOTSOLARIS) $(SRCDIR)/%
	$(INS.file)

$(BOOTDEVICEDB):
	$(INS) -s -d -m $(DIRMODE) $@

$(BOOTDEVICEDB)/%: $(BOOTDEVICEDB) $(SRCDIR)/%
	$(INS.file)

$(SRCDIR)/priv_names: $(PRIVS_DEF) $(PRIVS_AWK)
	$(NAWK) -f $(PRIVS_AWK) < $(PRIVS_DEF) -v pnamesfile=$@

clean lint:
clobber: clobber.targ

# 
#	No lints, so keep the clobber and clean targets reasonable. 
# 
CLEANLINTFILES	= Nothing_to_remove
CLEANFILES	= Nothing_to_remove
CLOBBERFILES	= $(SRCDIR)/priv_names

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ
