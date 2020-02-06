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
# Copyright 1989-2002 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/lp/filter/postscript/font/Makefile
#

include			../../../Makefile.lp

PROG =			makedev

SRCS =			makedev.c

OBJS =			$(SRCS:%.c=%.o)

SUBDIRS =		devpost

COMMONDIR =		../common
ROOTLIBFONT =		$(ROOTLIB)/font
ROOTLIBFONTPROG =	$(PROG:%=$(ROOTLIBFONT)/%)

CPPFLAGS =		-I$(COMMONDIR) $(CPPFLAGS.master)

POFILE =	lp_filter_postscript_font.po

NATIVEDIR =		native
NATIVEPROG =		$(NATIVEDIR)/$(PROG)
NATIVE_LIBS +=		libc.so
$(NATIVEPROG) :=	CC=$(NATIVECC)
$(NATIVEPROG) :=	LDLIBS=
$(NATIVEPROG) :=	CPPFLAGS.master=

.KEEP_STATE:

all :			$(PROG) $(NATIVEPROG) $(SUBDIRS)

install :		$(PROG) $(ROOTLIBFONTPROG) $(SUBDIRS)

clean :			$(SUBDIRS)
			$(RM) $(OBJS)

clobber :		$(SUBDIRS) clean
			$(RM) $(PROG) $(NATIVEPROG) $(CLOBBERFILES)

strip:
			$(STRIP) $(PROG)

lint:
			$(LINT.c) $(SRCS)

include		../Makefile.msg

$(NATIVEPROG) :		$(NATIVEDIR) $(SRCS)
			$(LINK.c) -o $@ $(SRCS) $(LDLIBS)

$(NATIVEDIR) :
			-@mkdir -p $@

$(ROOTLIBFONT)/%:	%
			$(INS.file)

$(PROG) :		$(SRCS)
			$(LINK.c) -o $@ $(SRCS) $(LDLIBS)
			$(POST_PROCESS)

$(SUBDIRS):		FRC
			@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
