#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

.KEEP_STATE:

PROG = ctfstrip
SRCS = \
	ctfstrip.c 

CFLAGS += $(CCVERBOSE)
include $(SRC)/tools/Makefile.tools

OBJS = $(SRCS:%.c=%.o)
LINTFILES = $(SRCS:%.c=%.ln)

LINTFLAGS = -mnux -L$(ROOT)/usr/lib

.NO_PARALLEL:
.PARALLEL: $(OBJS) $(LINTFILES)

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(ROOTONBLDMACHPROG): $(PROG)

install: $(ROOTONBLDMACHPROG)

clean:
	$(RM) $(OBJS) $(LINTFILES)

lint: $(LINTFILES)
	$(LINT) $(LINTFLAGS) $(LINTFILES) $(LDLIBS)

include $(SRC)/tools/Makefile.targ
