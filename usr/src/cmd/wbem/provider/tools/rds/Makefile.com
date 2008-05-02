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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/wbem/provider/tools/rds/Makefile.com
#


PROG = rds
OBJS = rds.o rdutil.o rdfile.o rdtable.o rdimpl.o rdprot.o rdlist.o prtelement.o
SRCS = $(OBJS:%.o=../%.c)

include $(SRC)/cmd/wbem/Makefile.cmd

CPPFLAGS += -D_REENTRANT
CFLAGS += $(CCVERBOSE)
CFLAGS64 += $(CCVERBOSE)
LDLIBS += -lproject
LINTFLAGS += -u
LINTFLAGS64 += -u

# i.e. permission and group for /usr/bin-style executables
FILEMODE = 0555
GROUP = bin

.KEEP_STATE:

.PARALLEL : $(OBJS)

all: $(PROG)

test:
	echo WBEMPROG32 $(ROOTWBEMPROG32)

clean:
	$(RM) $(OBJS)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o:	../%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

lint:
	$(LINT.c) $(SRCS) $(LDLIBS)

include $(SRC)/cmd/Makefile.targ
