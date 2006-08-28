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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include $(SRC)/Makefile.master

DATAFILES=copyright
TMPLFILES= pkginfo
CHKINSTALLSRC=
CHKINSTALL=$(CHKINSTALLSRC:%=checkinstall)

FILES=$(CHKINSTALL) $(DATAFILES) $(TMPLFILES)

PACKAGE:sh= basename `pwd`

CLOBBERFILES= $(FILES)

# The following is some magic to generate the list of files that a package
# depends on (i.e., contains).  The basic idea is to invoke an awk script
# using the $(...:sh) make construct.  The awk script extracts the relevant
# file names from the prototype file(s), following "include" directives as
# needed.  For path1=path2 constructs, use path2, because that's where
# we'll actually find the file.  Type e, f, and v files are in the proto
# area.  Type i files are in the current directory.

INCLPROC= /^!include/ {ARGV[ARGC]=$$2; ARGC += 1}
EFVPROC= /^[efv] / {sub(/.*=/, "", $$3); print $$3}
IPROC= /^i / {sub(/.*=/, "", $$2); print $$2}
PKGFILESCMD= nawk '$(INCLPROC) $(EFVPROC)' prototype_$(MACH)
PKGIFILESCMD= nawk '$(INCLPROC) $(IPROC)' prototype_$(MACH)
PKGFILESCONTENTS= $(PKGFILESCMD:sh)
PKGIFILES= $(PKGIFILESCMD:sh)
ROOTPKGCONTENTS=$(PKGFILESCONTENTS:%=$(ROOT)/%)
