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
# Copyright 1989-2002 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/lp/filter/postscript/postreverse/Makefile
#

include         ../../../Makefile.lp

PROG =           postreverse

SRCS =		postreverse.c

OBJS =		$(SRCS:%.c=%.o)

TXTS=		README 

ENCODING =	2
CPPFLAGS =	-DDFLTENCODING=$(ENCODING)	\
		-I. -I$(COMMONDIR) 		\
		$(CPPFLAGS.master)

POFILE =	lp_filter_postscript_postreverse.po

.KEEP_STATE :

all :		$(TXTS) $(PROG)

$(PROG) : 	$(OBJS)
		$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
		$(POST_PROCESS)

install :	all $(ROOTLIBLPPOSTPROG)

clean :
		$(RM) $(OBJS)

strip :
		$(STRIP) $(PROG)

lint :		lint_SRCS

include		../../../../Makefile.targ

include		../Makefile.msg
