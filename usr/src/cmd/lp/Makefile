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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include 	./Makefile.lp

SUBDIRS =	filter crontab terminfo lib cmd model

MSGSUBDIRS =	filter lib cmd model

ROOTDIRS =					\
		$(ROOTLIBLP)			\
		$(ROOTLIBLP)/bin		\
		$(ROOTLIBLP)/model		\
		$(ROOTLIBLPLOCL)		\
		$(ROOTLIB)/print		\
		$(LPOWNSDIRS)
LPOWNSDIRS =					\
		$(ROOTETCLP)			\
		$(ROOTETCLP)/classes		\
		$(ROOTETCLP)/forms		\
		$(ROOTETCLP)/interfaces		\
		$(ROOTETCLP)/printers		\
		$(ROOTETCLP)/pwheels		\
		$(ROOTETCLP)/ppd		\
		$(ROOTVAR)/lp			\
		$(ROOTVAR)/lp/logs		\
		$(ROOTVARSP)/lp			\
		$(ROOTVARSP)/lp/admins		\
		$(ROOTVARSP)/lp/requests 	\
		$(ROOTVARSP)/lp/system

SYMDIR1 =	$(ROOTVARSP)/lp/admins/lp
SYMDIR2 =	$(ROOTVARSP)/lp/bin
SYMDIR3 =	$(ROOTVARSP)/lp/logs
SYMDIR4 =	$(ROOTETCLP)/logs
SYMDIR5 =	$(ROOTVARSP)/lp/model

$(SYMDIR1) :=	SYMLNKDEST =	../../../../etc/lp
$(SYMDIR2) :=	SYMLNKDEST =	../../../usr/lib/lp/bin
$(SYMDIR3) :=	SYMLNKDEST =	../../lp/logs
$(SYMDIR4) :=	SYMLNKDEST =	../../var/lp/logs
$(SYMDIR5) :=	SYMLNKDEST =	../../../usr/lib/lp/model

ROOTSYMLINKDIRS =	$(SYMDIR1) $(SYMDIR2) $(SYMDIR3) $(SYMDIR4) $(SYMDIR5)

$(ROOTVAR)/lp :=		DIRMODE = 775
$(ROOTVAR)/lp/logs :=		DIRMODE = 775
$(ROOTETCLP) :=			DIRMODE = 775
$(ROOTETCLP)/classes :=		DIRMODE = 775
$(ROOTETCLP)/forms :=		DIRMODE = 775
$(ROOTETCLP)/interfaces :=	DIRMODE = 775
$(ROOTETCLP)/printers :=	DIRMODE = 775
$(ROOTETCLP)/pwheels :=		DIRMODE = 775
$(ROOTETCLP)/ppd :=		DIRMODE = 775
$(ROOTVARSP)/lp :=		DIRMODE = 775
$(ROOTVARSP)/lp/admins :=	DIRMODE = 775
$(ROOTVARSP)/lp/requests :=	DIRMODE = 775
$(ROOTVARSP)/lp/system :=	DIRMODE = 775
$(ROOTLIB)/print :=		DIRMODE = 0755

POFILE= lp.po
POFILES= lp_*.po

.KEEP_STATE:

all:	$(TXTS) $(SUBDIRS)

#
# Each message catalog file is generated in each sub
# directory and copied to the usr/src/cmd/lp/ directory.
# Those message catalog files are consolidated into one
# message catalog file.  The consolidated one will be copied
# into the $(ROOT)/catalog/SUNW_OST_OSCMD/ directory.
#

_msg:	$(MSGDOMAINPOFILE)

$(POFILE):	$(MSGSUBDIRS) pofile_POFILES

install: $(ROOTDIRS) $(ROOTSYMLINKDIRS) $(SUBDIRS)

clean strip lint: $(SUBDIRS)

clobber: $(SUBDIRS) local_clobber

local_clobber:
	$(RM) $(CLOBBERFILES)

$(ROOTDIRS) :
	$(INS.dir)

$(ROOTSYMLINKDIRS) :
	-$(RM) $@; $(SYMLINK) $(SYMLNKDEST) $@

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include $(SRC)/Makefile.msg.targ
