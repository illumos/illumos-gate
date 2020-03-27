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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Makefile for libc-related x86 flarcreate precreation scripts
#
#
# libc/i386_etc/Makefile

include ../../../../Makefile.master

FLASHPRESRC=	caplib.ksh
FLASHPREPROG=	$(FLASHPRESRC:%.ksh=%)

all:=           TARGET= all
install:=       TARGET= install
clean:=         TARGET= clean
clobber:=       TARGET= clobber

ROOTETC=	$(ROOT)/etc
ETCFLASHD=	$(ROOTETC)/flash
ETCFLASHPREC=	$(ROOTETC)/flash/precreation
ETCFLASHPREE=	$(ROOTETC)/flash/preexit
ETCFLASHPOSTC=	$(ROOTETC)/flash/postcreation

DIRS=		$(ETCFLASHPREC) $(ETCFLASHPREE) $(ETCFLASHPOSTC)

ETCFLASHPREPROG=	$(FLASHPREPROG:%=$(ETCFLASHPREC)/%)

$(ETCFLASHD) :=	DIRMODE=	755
$(ETCFLASHPREC) :=	DIRMODE=	700
$(ETCFLASHPREE) :=	DIRMODE=	700
$(ETCFLASHPOSTC) :=	DIRMODE=	700
$(ETCFLASHPREPROG) :=	FILEMODE=       0500

.KEEP_STATE:

all: $(FLASHPREPROG)

install: all .WAIT $(DIRS) .WAIT $(ETCFLASHPREPROG)

cstyle:


$(FLASHPREPROG): $(FLASHPRESRC)
	$(CP) $@.ksh $@

$(DIRS):
	$(INS.dir)

$(ETCFLASHPREC)/% : %
	$(INS.file)

$(ETCFLASHPREE)/% : %
	$(INS.file)

$(ETCFLASHPOSTC)/% : %
	$(INS.file)

clean:
	$(RM) $(FLASHPREPROG)

clobber: clean
	$(RM) $(ETCFLASHPREPROG)
