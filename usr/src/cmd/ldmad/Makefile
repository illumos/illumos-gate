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
#
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG=		ldmad
MANIFEST=	ldoms-agents.xml
SVCMETHOD=	ldoms-agents

include ../Makefile.cmd

SRCS=		ldmad.c			\
		ldma_log.c		\
		ldma_device.c		\
		ldma_system.c		\
		ldma_dio.c		\
		mdesc_lib.c


OBJS=		$(SRCS:%.c=%.o)

ROOTCMDDIR=		$(ROOTLIB)/ldoms
ROOTMANIFESTDIR=	$(ROOTSVCPLATFORMSUN4V)
$(ROOTMANIFEST)		:= FILEMODE= 444

LDLIBS +=	-lds -ldladm -ldevinfo
INCS +=		-I$(ROOT)/usr/platform/sun4v/include/sys
CPPFLAGS += 	$(INCS)
C99MODE =	$(C99_ENABLE)

.KEEP_STATE:

all: $(PROG) 

$(PROG): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

install: all .WAIT $(ROOTCMD) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

check: $(CHKMANIFEST)

lint: lint_SRCS

clean:
	$(RM) $(PROG) $(OBJS) $(LINT_FILES)

include ../Makefile.targ
