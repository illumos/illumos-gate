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
# Copyright 1998-2002 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

OBJS=		ifaddrlist.o 

SRCS=		$(OBJS:.o=.c)
HDRS=		ifaddrlist.h

include	../../Makefile.cmd

CPPFLAGS +=	-O -I. 

.KEEP_STATE:

all:	$(OBJS)

clean:	
	$(RM) $(OBJS)

lint:	lint_SRCS

install:	all

# When an internationalized code is added to this directory, _msg has to be
# defined in order to generate message catalog. Also, move 'common' directory
# from 'SUBDIR1' to 'SUBDIR2' in usr/src/cmd/cmd-inet/Makefile

include ../../Makefile.targ
