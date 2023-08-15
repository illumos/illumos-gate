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

PROG=		rm
XPG4PROG=	rm
RMOBJ1=		rm.o
RMOBJ=		$(RMOBJ1) getresponse.o
XPG4RMOBJ=	$(RMOBJ:%.o=xpg4_%.o)
SRCS= 		$(RMOBJ1:%.o=%.c) $(SRC)/common/util/getresponse.c

include ../Makefile.cmd

CFLAGS += $(CCVERBOSE)
CERRWARN += -_gcc=-Wno-parentheses
$(XPG4) := CFLAGS += -DXPG4
CPPFLAGS += -D_FILE_OFFSET_BITS=64  -I $(SRC)/common/util
LINTFLAGS += -u
.KEEP_STATE:

all: $(PROG) $(XPG4)

install: all $(ROOTPROG) $(ROOTXPG4PROG)

$(PROG): $(RMOBJ)
	$(LINK.c) $(RMOBJ) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(XPG4): $(XPG4RMOBJ)
	$(LINK.c) $(XPG4RMOBJ) -o $@ $(LDLIBS)
	$(POST_PROCESS)

%.o:    $(SRC)/common/util/%.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POST_PROCESS_O)

xpg4_%.o:	%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

xpg4_%.o:	$(SRC)/common/util/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

clean:
	$(RM) $(RMOBJ) $(XPG4RMOBJ)

lint:	lint_SRCS

include ../Makefile.targ
