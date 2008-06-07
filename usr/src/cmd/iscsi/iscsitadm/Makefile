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
#ident	"%Z%%M%	%I%	%E% SMI"
#

PROG = iscsitadm
OBJS = main.o helper.o cmdparse.o
SRCS =$(OBJS:%.o=%.c)
POFILES= $(OBJS:%.o=%.po)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/iscsi/Makefile.iscsi

LDLIBS += -liscsitgt
XMLLIB = -lxml2
CFLAGS += $(CCVERBOSE) -I${ISCSICOMMONDIR}
FILEMODE= 0555
GROUP= bin

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTUSRSBINPROG)

$(PROG): $(OBJS) $(COMMON_OBJS)
	$(LINK.c) -o $(PROG) $(OBJS) $(COMMON_OBJS) $(LDLIBS) $(XMLLIB)
	$(POST_PROCESS)

catalog:	$(POFILE)

lint	:= LINTFLAGS += -u
lint	:= LINTFLAGS64 += -u

lint:	$$(SRCS)
	$(LINT.c) $(SRCS) $(LDLIBS)

$(POFILE): $(POFILES)
	$(RM) $@
	cat $(POFILES) > $@

%.o : $(ISCSICOMMONDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

clean:
	-$(RM) $(OBJS) $(COMMON_OBJS) 

include $(SRC)/cmd/Makefile.targ
