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

PROG =		prophist
OBJS =		prophist.o \
		manifest_hash.o
LNTS =		$(OBJS:%.o=%.ln)
POFILES =	$(OBJS:%.o=%.po)

SRCS =		prophist.c \
		../common/manifest_hash.c

POFILES = 	$(OBJS:.o=.po)

include ../../Makefile.cmd
include ../../Makefile.ctf

ROOTCMDDIR=     $(ROOT)/lib/svc/bin

ROOTPROPHIST=	$(ROOT)/var/svc/profile/prophist.SUNWcsr

$(ROOTPROPHIST) := FILEMODE = 0444

CPPFLAGS +=	-I../common
LDLIBS +=	-lscf -luutil -lmd5
CLOBBERFILES += $(POFILES)

lint := LINTFLAGS = -mux

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTCMD) $(ROOTPROPHIST)

clean:
	$(RM) $(OBJS) $(POFILES) $(LNTS)

lint: $(LNTS)
	$(LINT.c) $(LINTFLAGS) $(LNTS) $(LDLIBS)

%.o: ../common/%.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POST_PROCESS_O)

%.ln: ../common/%.c
	$(LINT.c) $(OUTPUT_OPTION) -c $<

$(ROOT)/var/svc/profile/%: %
	$(INS.file)

include ../../Makefile.targ
