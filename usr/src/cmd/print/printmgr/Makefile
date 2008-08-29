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

#
# Makefile for print manager
#
PROG =		pmserver.jar pmclient.jar

include		$(SRC)/cmd/Makefile.cmd

SUBDIRS =	com bin

all	:=	TARGET= all
install	:=	TARGET= install
clean	:=	TARGET= clean
clobber	:=	TARGET= clobber
lint	:=	TARGET= lint
_msg	:=	TARGET= _msg

ROOTDIRS =	$(ROOT)/usr/sadm/admin \
		$(ROOT)/usr/sadm/admin/printmgr \
		$(ROOT)/usr/sadm/admin/printmgr/classes

ROOTBIN =	$(ROOT)/usr/sadm/admin/printmgr/classes
ROOTBINPROG =   $(PROG:%=$(ROOTBIN)/%)
ROOTAPPDIR =	$(ROOT)/usr/share/applications
ROOTAPPFILE =	$(ROOTAPPDIR)/solaris-print-manager.desktop

$(ROOTAPPFILE):= FILEMODE	= 444

$(ROOTBINPROG):= FILEMODE	= 644
$(ROOTBINPROG):= OWNER		= root
$(ROOTBINPROG):= GROUP		= lp

.KEEP_STATE:

all:		$(SUBDIRS)
install:	$(SUBDIRS) $(ROOTDIRS) $(ROOTBINPROG) $(ROOTAPPFILE) .WAIT links

links:
		$(RM) $(ROOTUSRSBIN)/printmgr
		$(SYMLINK) ../../usr/sadm/admin/bin/printmgr \
			$(ROOTUSRSBIN)/printmgr

clean clobber:	$(SUBDIRS)
	-$(RM) $(PROG)

lint _msg:	$(SUBDIRS)

strip:

$(PROG): FRC
	@if [ $@ = "pmclient.jar" ]; \
	then $(JAR) cf $@ \
		com/sun/admin/pm/client/*class \
		com/sun/admin/pm/client/images/*gif 2>/dev/null; \
	else $(JAR) cf $@ \
		com/sun/admin/pm/server/*class 2>/dev/null; \
	fi

$(ROOTAPPDIR)/%:	%
	$(INS.file)

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

$(ROOTDIRS):
	$(INS.dir)

$(ROOTBIN)/%: %
	$(INS.file)

FRC:
