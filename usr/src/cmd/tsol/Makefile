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
# cmd/tsol/Makefile
#

include ../Makefile.cmd

SUBDIRS =		\
	atohexlabel	\
	getlabel	\
	demo		\
	misc		\
	zones		\
	labeld		\
	updatehome	\
	plabel		\
	setlabel	\
	tnchkdb		\
	tninfo		\
	tnctl		\
	tnd		\
	tsol-zones	\
	getzonepath	\
	hextoalabel	\
	lslabels


MSGSUBDIRS =		\
	getlabel	\
	setlabel	\
	tnchkdb		\
	tninfo		\
	tnctl		\
	tnd		\
	getzonepath

#
# for messaging catalog
#
POFILE= tsol-cmd.po
POFILES= $(MSGSUBDIRS:%=%/%.po)

all	:=	TARGET = all
install :=	TARGET = install
clean	:=	TARGET = clean
clobber	:=	TARGET = clobber
lint	:=	TARGET = lint
_msg	:=	TARGET = _msg

.KEEP_STATE:

.PARALLEL:	$(SUBDIRS)

all install clean clobber lint: $(SUBDIRS)

$(POFILE): $(MSGSUBDIRS) $(CLOSED_MSGSUBDIRS)
	$(RM) $(POFILE)
	$(CAT) $(POFILES) > $(POFILE)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include Makefile.targ
