#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# psm/stand/boot/Makefile.boot

#
# Hack until stand makefiles are fixed
#
CLASS	= 32

include $(TOPDIR)/Makefile.master
include $(TOPDIR)/Makefile.psm

STANDDIR	= $(TOPDIR)/stand
PSMSTANDDIR	= $(TOPDIR)/psm/stand

SYSHDRDIR	= $(STANDDIR)
SYSLIBDIR	= $(ROOT)/stand/lib

PSMSYSHDRDIR	= $(PSMSTANDDIR)
PSMNAMELIBDIR	= $(PSMSTANDDIR)/lib/names/$(MACH)
PSMNAMELIBDIR64	= $(PSMSTANDDIR)/lib/names/$(MACH64)
PSMPROMLIBDIR	= $(PSMSTANDDIR)/lib/promif/$(MACH)
PSMPROMLIBDIR64	= $(PSMSTANDDIR)/lib/promif/$(MACH64)

#
# XXX	one day we should just be able to set PROG to 'cfsboot'..
#	and everything will become a lot easier.
#
# XXX	note that we build but -don't- install the HSFS boot
#	program - it's unused and untested, and until it is we
#	shouldn't ship it!
#
UNIBOOT		= multiboot
UFSBOOT		= ufsboot
WANBOOT		= wanboot
NFSBOOT		= inetboot
HSFSBOOT	= hsfsboot

#
# Common install modes and owners
#
FILEMODE	= 644
DIRMODE		= 755
OWNER		= root
GROUP		= sys

#
# Install locations
#
ROOT_PSM_UNIBOOT= $(ROOT_PSM_DIR)/$(UNIBOOT)
ROOT_PSM_UFSBOOT= $(ROOT_PSM_DIR)/$(UFSBOOT)
ROOT_PSM_WANBOOT= $(ROOT_PSM_DIR)/$(WANBOOT)
USR_PSM_NFSBOOT	= $(USR_PSM_LIB_NFS_DIR)/$(NFSBOOT)
USR_PSM_HSFSBOOT= $(USR_PSM_LIB_HSFS_DIR)/$(HSFSBOOT)

#
# While things are pretty much 32-bit lint-clean, there are a ton of
# suspect pointer casts.  Since these may be serious problems (especially
# on SPARC), this really needs to be investigated thoroughly one day.
# However, we shouldn't feel too bad: the whole kernel is linted with this
# turned off as well (along with a dozen other disabled warnings).
#
# The other two -erroff's are needed only because lint's -u flag is lame
# and also turns off "name used but not defined" checks (so we instead
# just enumerate the errors that -u turns off that we want turned off).
#
LINTFLAGS = -nmsF -erroff=E_BAD_PTR_CAST_ALIGN \
	    -erroff=E_NAME_DECL_NOT_USED_DEF2 -erroff=E_NAME_DEF_NOT_USED2
