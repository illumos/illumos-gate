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

MANIFEST  = group.xml

PROG= sharemgr

include ../../Makefile.cmd

#
# To build sharemgr as both 32- and 64-bit objects, using isaexec, set
# SHAREMGR64= in your build environment.
#
SHAREMGR64= $(POUND_SIGN)

#
# One for each ISA.
#
SUBDIRS =	$(MACH)
$(SHAREMGR64)$(BUILD64)SUBDIRS += $(MACH64)

LINKS= share unshare
ROOTLINKS= $(LINKS:%=$(ROOTUSRSBIN)/%)
ROOTLINKS32= $(LINKS:%=$(ROOTUSRSBIN32)/%)
ROOTLINKS64= $(LINKS:%=$(ROOTUSRSBIN64)/%)
$(SHAREMGR64)ROOTLINKS += $(ROOTLINKS32) $(ROOTLINKS64)

ROOTMANIFESTDIR	= $(ROOTSVCNETWORKSHARES)
$(ROOTMANIFEST)		:= FILEMODE= 444

all	:=	TARGET= all
install	:=	TARGET= install
clean	:=	TARGET= clean
clobber	:=	TARGET= clobber
_msg	:=	TARGET= _msg
lint	:=	TARGET= lint

.KEEP_STATE:

all clean clobber lint _msg:	$(SUBDIRS)

install: $(SUBDIRS) $(ROOTMANIFEST) .WAIT $(ROOTLINKS)

$(ROOTLINKS): FRC
	-$(RM) $@
	-$(LN) $(@D)/$(PROG) $@

check:	$(CHKMANIFEST)

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
