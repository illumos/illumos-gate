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
# Copyright 2025 Hans Rosenfeld

.KEEP_STATE:
.SUFFIXES:

include ../../Makefile.cmd

COMMON_DIR=	../common	# for Makefile.com
OBJS =		rcapadm.o $(COMMON_OBJS)
SRCS =		$(OBJS:%.o=%.c)

COMMON_OBJS =	rcapd_stat.o utils.o rcapd_conf.o
CLEANFILES =	$(OBJS) $(COMMON_OBJS:%.o=%.c)

$(NOT_RELEASE_BUILD)CPPFLAGS	+= -DDEBUG
CPPFLAGS			+= -I$(COMMON_DIR)
LDLIBS				+= -lumem -lscf -lzonecfg

PROG =		rcapadm

POFILES =	$(OBJS:%.o=%.po)
POFILE =	p$(PROG).po

all: $(PROG)

include ../Makefile.com

$(PROG): $(OBJS) $(MAPFILE.NGB)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

clean:
	$(RM) $(CLEANFILES)

$(ROOTUSRSBIN):
	$(MKDIR) -p $(ROOTUSRSBIN)

install: all $(ROOTUSRSBIN) $(ROOTUSRSBINPROG)

include ../../Makefile.targ
