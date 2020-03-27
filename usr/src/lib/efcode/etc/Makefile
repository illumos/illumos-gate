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
# Efcode cleanup
# Disable efdaemon on target systems not supporting Embedded Fcode Interpreter
# Enable  efdaemon on target systems supporting Embedded Fcode Interpreter
#

include $(SRC)/Makefile.master

FLASHPOSTDSRC=  efcode.cleanup.sh
FLASHPOSTDPROG= $(FLASHPOSTDSRC:%.sh=%)
#
#

all:=           TARGET= all
install:=       TARGET= install
clean:=         TARGET= clean
clobber:=       TARGET= clobber

ROOTETC= $(ROOT)/etc
ETCFLASHD=      $(ROOTETC)/flash
ETCFLASHPOSTD=	$(ROOTETC)/flash/postdeployment

DIRS=   $(ETCFLASHD) $(ETCFLASHPOSTD)

ETCFLASHPOSTDPROG= $(FLASHPOSTDPROG:%=$(ETCFLASHPOSTD)/%)

$(ETCFLASHD)		:= DIRMODE=	755
$(ETCFLASHPOSTD)	:= DIRMODE=	755
$(ETCFLASHPOSTDPROG)	:= FILEMODE=	0744

.KEEP_STATE:

all:	$(FLASHPOSTDPROG)

install: all .WAIT $(DIRS) $(ETCFLASHPOSTDPROG)

$(DIRS):
	$(INS.dir)

$(ETCFLASHPOSTD)/%: %
	$(INS.file)

clean:

clobber: clean
	$(RM) $(FLASHPOSTDPROG)
	$(RM) $(ETCFLASHPOSTD)/$(FLASHPOSTDPROG)
