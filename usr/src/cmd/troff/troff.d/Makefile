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
# cmd/troff/troff.d/Makefile
#
# Copyright (c) 2019, Joyent, Inc.

include 	../../Makefile.cmd

PROG =		troff ta makedev

SUBDIRS =	tmac.d

TAOBJS =	draw.o ta.o
MAKEDEVOBJS =	makedev.o
TROFFOBJS =	t10.o t6.o
COMMONOBJS =	hytab.o n1.o n2.o n3.o n4.o n5.o		\
		n7.o n8.o n9.o ni.o nii.o suftab.o

SRCS =		$(TAOBJS:%.o=%.c) $(MAKEDEVOBJS:%.o=%.c)	\
		$(TROFFOBJS:%.o=%.c) $(COMMONOBJS:%.o=../%.c)

TXTS =		README maketables troff.sh

CPPFLAGS =	-DUSG -DINCORE -I. -I.. $(CPPFLAGS.master)

CERRWARN +=	-_gcc=-Wno-implicit-function-declaration
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	$(CNOWARN_UNINIT)
CERRWARN +=	-_gcc=-Wno-extra

# "parse error: parsing (i (9223372034707292160-96) >= 65)"
SMATCH =	off

#
# For message catalog
#
POFILES= $(TROFFOBJS:%.o=%.po) $(COMMONOBJS:%.o=../%.po)
POFILE= troff.d.po

# conditional assignments

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
lint :=		TARGET= lint
strip :=	TARGET= strip

troff:=		POBJS=	$(COMMONOBJS) $(TROFFOBJS)
ta:=		POBJS=	$(TAOBJS)
makedev:=	POBJS=	$(MAKEDEVOBJS)

ta:=		LDLIBS += -lm
troff:=		LDLIBS += -lmapmalloc

# build rule for common source above
%.o: ../%.c
		$(COMPILE.c) $<

.KEEP_STATE:

.PARALLEL: $(COMMONOBJS) $(TROFFOBJS) $(TAOBJS) $(MAKEDEVOBJS)

all :		$(PROG) $(TXTS) $(SUBDIRS)

$(PROG) :	$$(POBJS)
		$(LINK.c) -o $@ $(POBJS) $(LDLIBS)
		$(POST_PROCESS)

install:	$(PROG) $(ROOTPROG) $(SUBDIRS)

clean:		$(SUBDIRS)
		$(RM) $(TAOBJS) $(MAKEDEVOBJS) $(TROFFOBJS) $(COMMONOBJS)

catalog:        $(POFILE)

$(POFILE):      $(POFILES)
	$(RM)	$@
	cat     $(POFILES)      > $@


strip :
		$(STRIP $(PROG)

lint :		lint_SRCS

include		../../Makefile.targ

# additional dependency for clobber which is defined in Makefile.targ
clobber:	$(SUBDIRS)

$(SUBDIRS) :	FRC
		@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
