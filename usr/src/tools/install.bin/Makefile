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

PROG=	install.bin
OBJS=	$(PROG).o stdusers.o
SRCS=	$(PROG).c ../protocmp/stdusers.c

include ../Makefile.tools

CFLAGS += $(CCVERBOSE)
CERRWARN += -_gcc=-Wno-type-limits
CPPFLAGS += -I../protocmp
LDLIBS += -lgen
CLEANFILES += $(OBJS)

# Assume we don't have the install.bin available yet
INS.file=	$(RM) $@; $(CP) $< $(@D); $(CHMOD) $(FILEMODE) $@

.KEEP_STATE:

all:	$(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)


install: all .WAIT $(ROOTONBLDMACHPROG)
	$(RM) $(ROOTONBLDBINMACH)/install
	$(LN) $(ROOTONBLDMACHPROG) $(ROOTONBLDBINMACH)/install

lint:	lint_SRCS

clean:
	$(RM) $(CLEANFILES)

%.o: ../protocmp/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../Makefile.targ
