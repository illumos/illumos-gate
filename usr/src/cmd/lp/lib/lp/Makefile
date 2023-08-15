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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/lp/lib/lp/Makefile
#

LIBRARY	=	liblp.a

OBJECTS =	Syscalls.o	\
		Sys_malloc.o	\
		addlist.o	\
		addstring.o	\
		appendlist.o	\
		alerts.o	\
		charset.o	\
		cs_strcmp.o	\
		cs_strncmp.o	\
		dellist.o	\
		dashos.o	\
		dirs.o		\
		duplist.o	\
		files.o		\
		freelist.o	\
		getlist.o	\
		getname.o	\
		getpaths.o	\
		getspooldir.o	\
		isterminfo.o	\
		joinlist.o	\
		lenlist.o	\
		lp_errno.o	\
		makepath.o	\
		makestr.o	\
		mergelist.o	\
		next.o		\
		printlist.o	\
		sdn.o		\
		sprintlist.o	\
		searchlist.o	\
		set_charset.o	\
		set_pitch.o	\
		set_size.o	\
		sop.o		\
		strip.o		\
		syntax.o	\
		tidbit.o	\
		tx.o		\
		wherelist.o	\
		which.o


include		../../../../lib/Makefile.lib
include         ../../Makefile.lp

# Specifically request the construction of a static library.
# This library is not installed in the proto area.
LIBS = $(LIBRARY)

CPPFLAGS =	-I../../include $(CPPFLAGS.master) $(C_PICFLAGS)

POFILE =	lp_lib_lp.po

.KEEP_STATE:

all install :	$(LIBS)

include		../../../../lib/Makefile.targ

CLEANFILES	+= llib-llp.ln
LINTFLAGS = -nvx
SRCS= $(OBJECTS:%.o=%.c)
# lint does not take $(C_PICFLAGS)
LINT_CPPFLAGS =	-I../../include $(CPPFLAGS.master)

lint:	lintlib
	$(LINT) $(LINTFLAGS) $(LINT_CPPFLAGS) $(SRCS)

lintlib:
	$(LINT) $(LINTFLAGS) $(LINT_CPPFLAGS) -o lp llib-llp

include		../Makefile.msg
