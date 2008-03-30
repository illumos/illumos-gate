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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# psm/stand/bootblks/Makefile.com
#
TOPDIR = ../../../$(BASEDIR)

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
PSMPROMLIBDIR	= $(PSMSTANDDIR)/lib/promif/$(MACH)

#
# 'bootblk' is the basic target we build - in many flavours
#
PROG		= bootblk

#
# base prefix for the usr/platform bootblk links
#
BOOTBLK_LINK_PREFIX	=../../../../../../platform/$(PLATFORM)/lib/fs

#
# Used to convert Forth source to isa-independent FCode.
#
TOKENIZE	= tokenize

#
# Common install modes and owners
#
FILEMODE	= 444
DIRMODE		= 755
OWNER		= root
GROUP		= sys

#
# Lint rules (adapted from Makefile.uts)
#
LHEAD		= ( $(ECHO) "\n$@";
LGREP		= grep -v "pointer cast may result in improper alignment"
LTAIL		= ) 2>&1 | $(LGREP)
LINT_DEFS	+= -Dlint

#
# For building lint objects
#
LINTFLAGS.c	= -nsxum
LINT.c		= $(LINT) $(LINTFLAGS.c) $(LINT_DEFS) $(CPPFLAGS) -c
LINT.s		= $(LINT) $(LINTFLAGS.s) $(LINT_DEFS) $(CPPFLAGS) -c

#
# For building lint libraries
#
LINTFLAGS.lib	= -nsxum
LINT.lib	= $(LINT) $(LINTFLAGS.lib) $(LINT_DEFS) $(CPPFLAGS)

#
# For complete pass 2 cross-checks
# XXX: lint flags should exclude -u, but the standalone libs confuse lint.
#
LINTFLAGS.2	= -nsxum
LINT.2		= $(LINT) $(LINTFLAGS.2) $(LINT_DEFS) $(CPPFLAGS)
