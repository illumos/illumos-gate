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
$(ETCFLASHD) :=	DIRMODE=	755
$(ETCFLASHPRED) :=	DIRMODE=	755
$(ETCFLASHPOSTD) :=	DIRMODE=	755
$(ETCLVMINITPROG) :=	FILEMODE=       0644
$(ETCFLASHPREPROG) :=	FILEMODE=       0744
$(ETCFLASHPOSTPROG) :=	FILEMODE=       0744

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
