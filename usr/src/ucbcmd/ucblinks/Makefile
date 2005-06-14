#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright (c) 1998,2001 by Sun Microsystems, Inc.
# All rights reserved.
#
#ident	"%Z%%M%	%I%	%E% SMI"

PROG= ucblinks
OBJS= $(PROG).o

SHLIBEXFILES= ucblinks.sh
SHLIBFILES= ucblinks.awk

include ../Makefile.ucbcmd

ROOTLIBEXFILES= $(ROOTLIB)/$(SHLIBEXFILES)
ROOTLIBFILES= $(ROOTLIB)/$(SHLIBFILES)
GROUP = sys
$(ROOTLIBEXFILES)	:= FILEMODE = 555
$(ROOTLIBFILES)		:= FILEMODE = 644
$(ROOTLIB)	:= GROUP = bin
$(PROG)	:= GROUP = bin

LDLIBS += -ldevinfo

CLEANFILES += $(OBJS)


.KEEP_STATE:

all: $(PROG) $(SHLIBEXFILES) $(SHLIBFILES)

install: all $(ROOTPROG) $(ROOTLIB) $(ROOTLIBEXFILES) $(ROOTLIBFILES)

$(ROOTLIB):
	$(INS.dir)

clean:
	$(RM) $(CLEANFILES)

lint:

include ../Makefile.ucbtarg
