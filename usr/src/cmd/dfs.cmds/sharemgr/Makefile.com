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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include ../../../Makefile.cmd

SHAREMGR64= $(POUND_SIGN)
$(SHAREMGR64)SHAREMGRNO64= $(POUND_SIGN)

PROG=		sharemgr

OBJS	= sharemgr_main.o commands.o shareutil.o
SRCS	= $(OBJS:%.o=../%.c)

MYCPPFLAGS = -I../../../../lib/libfsmgt/common \
	-I$(ADJUNCT_PROTO)/usr/include/libxml2 \
		-I../..
CPPFLAGS += $(MYCPPFLAGS)
LDLIBS += -lshare -lscf -lsecdb -lumem
all install := LDLIBS += -lxml2
LINTFLAGS	+= -u

CERRWARN	+= -_gcc=-Wno-uninitialized

POFILES = $(SRCS:.c=.po)
POFILE  = sharemgr.po

LN_ISAEXEC= \
	$(RM) $(ROOTUSRSBINPROG); \
	$(LN) $(ISAEXEC) $(ROOTUSRSBINPROG)

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

install: all

$(SHAREMGRNO64)install: $(ROOTUSRSBINPROG)

lint:	lint_SRCS

clean:
	$(RM) $(OBJS)

include ../../../Makefile.targ

$(POFILE):      $(POFILES)
	$(RM) $@; cat $(POFILES) > $@

%.o: ../%.c
	$(COMPILE.c) $(OUTPUT_OPTION) $< $(CTFCONVERT_HOOK)
	$(POST_PROCESS_O)

FRC:
