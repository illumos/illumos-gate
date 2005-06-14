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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 1994-2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include ../Makefile.cmd

#
# Don't add new ptools here; these are legacy ptools which must be symlinked
# into /usr/proc/bin
#
LEGACY_SUBDIRS =\
	pcred	\
	pfiles	\
	pflags	\
	pldd	\
	pmap	\
	prun	\
	psig	\
	pstack	\
	pstop	\
	ptime	\
	ptree	\
	pwait	\
	pwdx

#
# 'new' ptools are not symlinked into /usr/proc/bin
#
NEW_SUBDIRS =	\
	pargs	\
	ppriv	\
	preap

SUBDIRS = $(LEGACY_SUBDIRS) $(NEW_SUBDIRS)

all	:=	TARGET = all
install	:=	TARGET = install
clean	:=	TARGET = clean
clobber	:=	TARGET = clobber
lint	:=	TARGET = lint

.KEEP_STATE:

.PARALLEL: $(SUBDIRS)

all install clean clobber lint: $(SUBDIRS)

$(NEW_SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) PTOOL_TYPE=NEW -f ../Makefile.ptool $(TARGET)

$(LEGACY_SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) PTOOL_TYPE=LEGACY -f ../Makefile.ptool $(TARGET)
FRC:
