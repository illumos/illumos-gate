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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
#  cmd/fs.d/cachefs/Makefile
#

SUBDIRS=	common \
		cfsadmin \
		cfsfstype \
		cfstagchk \
		fsck \
		mount \
		umount \
		cachefslog \
		cachefswssize \
		cachefsstat \
		cachefspack \
		mdbug \
		cfsd \
		dfshares \
		share \
		unshare

# MANIFESTS
# METHODS

# Zip Stuff
#SUBDIRS += 	cfscowchk \
#		cfscowchk \
#		cfscvtmnt \
#		cfslu \
#		cfspin \
#		cfsunpin 

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
lint :=		TARGET= lint

# include Makefile.cmd and Makefile.targ for _msg target
include ../../Makefile.cmd

POFILE= cachefs.po
GREP= grep
SED= sed

.KEEP_STATE:

all clean clobber lint: $(SUBDIRS)

install: $(SUBDIRS) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

check: $(CHKMANIFEST)

catalog: $(POFILE)

$(POFILE):
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext */*.[ch]`
	$(SED) "/^domain/d" < messages.po > $@
	$(RM) messages.po

local_clobber:
	$(RM) $(CLOBBERFILES)

FRC:

include ../../Makefile.targ
