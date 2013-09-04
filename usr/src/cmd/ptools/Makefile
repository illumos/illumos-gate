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
	plgrp	\
	pmadvise \
	ppriv	\
	preap

SUBDIRS = $(LEGACY_SUBDIRS) $(NEW_SUBDIRS)

all	:=	TARGET = all
install	:=	TARGET = install
clean	:=	TARGET = clean
clobber	:=	TARGET = clobber
lint	:=	TARGET = lint
_msg	:=	TARGET = _msg


# pmadvise depends on pmap components
PMAP =			$(SRC)/cmd/ptools/pmap
pmadvise/pmadvise.po :=	CPPFLAGS +=	-I$(PMAP)

#
# Commands with messages support
#
POFILES = plgrp/plgrp.po pmadvise/pmadvise.po
POFILE = ptools.po

.KEEP_STATE:

.PARALLEL: $(SUBDIRS)

all install clean lint: $(SUBDIRS)
clobber: $(SUBDIRS) clobber_local
clobber_local:
	$(RM) $(CLOBBERFILES)

$(NEW_SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) PTOOL_TYPE=NEW -f ../Makefile.ptool $(TARGET)

$(LEGACY_SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) PTOOL_TYPE=LEGACY -f ../Makefile.ptool $(TARGET)

#
# Combine all messages files into a single file and copy it to
# MSGDOMAIN directory
#
_msg: ${POFILES}
	$(RM) $(POFILE)
	$(CAT) $(POFILES) > $(POFILE)
	$(RM)  $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

FRC:
