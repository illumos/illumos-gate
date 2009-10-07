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

PROGFCOET	= svc-fcoet
PROGFCOEI	= svc-fcoei
PROG		= ${PROGFCOET} ${PROGFCOEI}

include ../Makefile.cmd

COMMONBASE	= ../../common

OBJSFCOET	= fcoetsvc.o
OBJSFCOEI	= fcoeisvc.o
SRCSFCOET	= $(OBJSFCOET:%.o=%.c)
SRCSFCOEI	= $(OBJSFCOEI:%.o=%.c)
SRCS		= $(SRCSFCOET) ${SRCSFCOEI}

LDLIBS		+= -lfcoe

MANIFEST	= fcoe_target.xml
MANIFEST	+= fcoe_initiator.xml
SVCMETHOD	= svc-fcoet
SVCMETHOD	+= svc-fcoei

ROOTMANIFESTDIR	= $(ROOTSVCSYSTEM)
$(ROOTSVCSYSTEM)/fcoe_target.xml	:= FILEMODE = 0444
$(ROOTSVCSYSTEM)/fcoe_initiator.xml	:= FILEMODE = 0444

.KEEP_STATE:

all: $(PROG)

$(PROGFCOET): $(OBJSFCOET)
	$(LINK.c) -o $@ $(OBJSFCOET) $(LDLIBS)
	$(POST_PROCESS)

$(PROGFCOEI): $(OBJSFCOEI)
	$(LINK.c) -o $@ $(OBJSFCOEI) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTMANIFEST) $(ROOTSVCMETHOD)

check:	$(CHKMANIFEST)
	$(CSTYLE) -pPc $(SRCS:%=%)

clean:
	$(RM) $(OBJSFCOET) ${OBJSFCOEI}

lint:
	$(LINT.c) $(SRCSFCOET) $(LDLIBS)
	$(LINT.c) $(SRCSFCOEI) ${LDLIBS}

include ../Makefile.targ
