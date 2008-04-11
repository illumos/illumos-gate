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
#ident	"%Z%%M%	%I%	%E% SMI"
#

include $(SRC)/Makefile.master

#
# DATAFILES enumerates files that are copied into the current directory
# from $(PKGDEFS)/common_files.  They are part of $(CLOBBERFILES).
#
DATAFILES=

TMPLFILES= pkginfo

#
# You should almost never mess with COPYRIGHT.  The only time you'll
# want to change this is when you have a single, handcrafted copyright
# file, and you reference it via "copyright=file" in your prototype_com.
#
# See usr/src/README.license-files for details.
#
COPYRIGHT=copyright

#
# These are the license files that are maintained in a common directory
# (usr/src/pkgdefs/license_files) because they're used by many different
# packages.  They're fair game for inclusion in LICENSEFILES (see below),
# and should be referenced by the macro names defined here.
#
CMN_LIC_DIR=$(PKGDEFS)/license_files
ATT=$(CMN_LIC_DIR)/cr_ATT
SUN=$(CMN_LIC_DIR)/cr_Sun
CDDL=$(CMN_LIC_DIR)/lic_CDDL
GPLV2=$(CMN_LIC_DIR)/lic_GPLv2
OSBL =	$(CMN_LIC_DIR)/lic_OSBL_preamble \
	$(SRC)/tools/opensolaris/BINARYLICENSE.txt
LIC_IN_HDRS=$(CMN_LIC_DIR)/license_in_headers

#
# LICENSEFILES enumerates, in order, the files that will be
# concatenated to generate a package copyright file.
#
# The default setting is Sun copyright, followed by CDDL.  See
# usr/src/README.license-files for individual settings and overrides.
#
# Most package Makefiles should append to this macro, rather than reset it.
#
LICENSEFILES=$(SUN) $(CDDL)

CHKINSTALLSRC=
CHKINSTALL=$(CHKINSTALLSRC:%=checkinstall)

FILES=$(COPYRIGHT) $(CHKINSTALL) $(DATAFILES) $(TMPLFILES)

PACKAGE:sh= basename `pwd`

CLOBBERFILES= $(FILES)
