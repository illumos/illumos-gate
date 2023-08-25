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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/lp/lib/msgs/Makefile
#

LIBRARY	=	liblpmsg.a

OBJECTS =	_getmessage.o	\
		_putmessage.o	\
		getmessage.o	\
		hslconv.o	\
		putmessage.o	\
		msgfmts.o	\
		mclose.o	\
		mconnect.o	\
		mdisconnect.o	\
		mgetputm.o	\
		mlisten.o	\
		mcreate.o	\
		mdestroy.o	\
		mneeds.o	\
		mopen.o		\
		mread.o		\
		mrecv.o		\
		msend.o		\
		mwrite.o	\
		streamio.o	\
		fifo_buffs.o	\
		read_fifo.o	\
		write_fifo.o


include		../../../../lib/Makefile.lib
include         ../../Makefile.lp

# Specifically request the construction of a static library.
# This library is not installed in the proto area.
LIBS = $(LIBRARY)

CPPFLAGS =	-I../../include $(CPPFLAGS.master) $(C_PICFLAGS) -D_TS_ERRNO

POFILE =	lp_lib_msgs.po

.KEEP_STATE:

all install :	$(LIBS)

include		../../../../lib/Makefile.targ

CLEANFILES	+= llib-llpmsg.ln
LINTFLAGS = -nvx
SRCS= $(OBJECTS:%.o=%.c)
LINT_CPPFLAGS =	-I../../include $(CPPFLAGS.master)

lint:	lintlib
	$(LINT) $(LINTFLAGS) $(LINT_CPPFLAGS) $(SRCS)

lintlib:
	$(LINT) $(LINTFLAGS) $(LINT_CPPFLAGS) -o lpmsg llib-llpmsg

include		../Makefile.msg
