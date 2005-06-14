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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Makefile for logical volume management 
#
#
# cmd/lvm/etc/Makefile


include ../../Makefile.cmd
include ../Makefile.lvm

FLASHPRESRC= svm.save.sh
FLASHPOSTSRC= svm.cleanup.sh
FLASHPREPROG= $(FLASHPRESRC:%.sh=%)
FLASHPOSTPROG= $(FLASHPOSTSRC:%.sh=%)
LVMINITPROG= md.cf md.ctlrmap md.tab mddb.cf lock runtime.cf devpath
#
#

all:=           TARGET= all
install:=       TARGET= install
clean:=         TARGET= clean
clobber:=       TARGET= clobber
lint:=          TARGET= lint

ETCLVMD= $(ROOTETC)/lvm
ETCFLASHD=	$(ROOTETC)/flash
ETCFLASHPRED=	$(ROOTETC)/flash/predeployment
ETCFLASHPOSTD=	$(ROOTETC)/flash/postdeployment

DIRS=	$(ETCLVMD) $(ETCFLASHD) $(ETCFLASHPRED) $(ETCFLASHPOSTD)

ETCLVMINITPROG= $(LVMINITPROG:%=$(ETCLVMD)/%)
ETCFLASHPREPROG= $(FLASHPREPROG:%=$(ETCFLASHPRED)/%)
ETCFLASHPOSTPROG= $(FLASHPOSTPROG:%=$(ETCFLASHPOSTD)/%)

$(ETCLVMD) :=	DIRMODE=	755
$(ETCLVMD) :=	OWNER=          root
$(ETCLVMD) :=	GROUP=          sys
$(ETCFLASHD) :=	DIRMODE=	755
$(ETCFLASHD) :=	OWNER=          root
$(ETCFLASHD) :=	GROUP=          sys
$(ETCFLASHPRED) :=	DIRMODE=	755
$(ETCFLASHPRED) :=	OWNER=          root
$(ETCFLASHPRED) :=	GROUP=          sys
$(ETCFLASHPOSTD) :=	DIRMODE=	755
$(ETCFLASHPOSTD) :=	OWNER=          root
$(ETCFLASHPOSTD) :=	GROUP=          sys
$(ETCLVMINITPROG) :=	FILEMODE=       0644
$(ETCLVMINITPROG) :=	OWNER=          root
$(ETCLVMINITPROG) :=	GROUP=          sys
$(ETCFLASHPREPROG) :=	FILEMODE=       0744
$(ETCFLASHPREPROG) :=	OWNER=          root
$(ETCFLASHPREPROG) :=	GROUP=          sys
$(ETCFLASHPOSTPROG) :=	FILEMODE=       0744
$(ETCFLASHPOSTPROG) :=	OWNER=          root
$(ETCFLASHPOSTPROG) :=	GROUP=          sys

.KEEP_STATE:

all: $(LVMINITPROG) $(FLASHPREPROG) $(FLASHPOSTPROG)

install: all .WAIT $(DIRS) .WAIT $(ETCLVMINITPROG)

install: all .WAIT $(DIRS) .WAIT $(ETCLVMINITPROG) \
	$(ETCFLASHPREPROG) $(ETCFLASHPOSTPROG)

cstyle:

lint:

$(DIRS):
	$(INS.dir)

$(ETCLVMD)/% : %
	$(INS.file)

$(ETCFLASHPRED)/% : %
	$(INS.file)

$(ETCFLASHPOSTD)/% : %
	$(INS.file)

clean:

clobber: clean
	$(RM) $(FLASHPREPROG) $(FLASHPOSTPROG)
