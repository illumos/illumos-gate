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
# Copyright 1990-2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

include         ../../Makefile.lp

LIBRARY =		liblpoam.a

TEXTOBJS =		e_adm__msgs.o	\
			e_can__msgs.o	\
			e_cmb__msgs.o	\
			e_fl__msgs.o	\
			e_for__msgs.o	\
			e_lp__msgs.o	\
			e_lpp__msgs.o	\
			e_lpu__msgs.o	\
			e_mov__msgs.o	\
			e_sht__msgs.o	\
			e_stat__msgs.o	\
			e_sys__msgs.o

OBJECTS =		agettxt.o	\
			buffers.o	\
			fmtmsg.o	\
			$(TEXTOBJS)

# see the comment below about the '+' signs in TEXTTARG
#
TEXTSRCS =		$(TEXTOBJS:%.o=%.c)
TEXTTARG =		$(TEXTSRCS:%=+ %)

TFILES =		msg.source gen-defs gen-text

TXTFILES=		$(TFILES)

LPINC =			../../include
OAMDEF_H =		$(LPINC)/oam_def.h

CLEANFILES =		$(TEXTSRCS) $(OAMDEF_H) xx??

include			../../../../lib/Makefile.lib

# Specifically request the construction of a static library.
# This library is not installed in the proto area.
LIBS = $(LIBRARY)

CPPFLAGS =		-I$(LPINC) $(CPPFLAGS.master)

# not linted
SMATCH=off

.KEEP_STATE:

all install :		$(TXTFILES) $(LIBS)

# derived source files
# and their dependencies
#
# beware of the hidden ordering requirement in the target source
# macros.  TEXTTARG contains '+' signs to tell make that this is a
# target group.  Without this syntax, an infinite build loop occurs.
#
$(OAMDEF_H) $(TEXTTARG) :$(TFILES)
			sh gen-defs > $(OAMDEF_H)
			sh gen-text

# dependencies slightly overstated but necessarily explicit
$(OBJS) $(PICS) :	$(OAMDEF_H) $$(@F:.o=.c)

include			../../../../lib/Makefile.targ

POFILE =		lp_lib_oam.po
XGETFLAGS +=	-a -x lp_lib_oam.xcl

CLEANFILES	+= llib-llpoam.ln
LINTFLAGS = -nvx
SRCS= $(OBJECTS:%.o=%.c)

lint:	lintlib
	$(LINT.c) $(LINTFLAGS) $(SRCS)

lintlib:
	$(LINT.c) $(LINTFLAGS) -o lpoam llib-llpoam

include		../Makefile.msg
