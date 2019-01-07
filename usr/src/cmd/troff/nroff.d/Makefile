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
# Copyright (c) 1989 by Sun Microsystems, Inc.
#
# Copyright (c) 2019, Joyent, Inc.

include 	../../Makefile.cmd

SUBDIRS =	terms.d

PROG =		nroff

OBJS =		n10.o n6.o

COMMONOBJS =	hytab.o n1.o n2.o n3.o n4.o n5.o	\
		n7.o n8.o n9.o ni.o nii.o suftab.o

SRCS =		$(OBJS:%.o=%.c) $(COMMONOBJS:%.o=../%.c)


CPPFLAGS =	-DNROFF -DUSG -DINCORE -DEUC -I. -I.. $(CPPFLAGS.master)

CERRWARN +=	-_gcc=-Wno-unused-value
CERRWARN +=	-_gcc=-Wno-extra
CERRWARN +=	-_gcc=-Wno-implicit-function-declaration
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-unused-variable

# parse error: parsing (i (9223372034707292160-96) >= 65)
SMATCH =	off

LDLIBS +=	-lmapmalloc
#
# message catalog
#
POFILES= $(OBJS:%.o=%.po)
POFILE= nroff.d.po


all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
lint :=		TARGET= lint
strip :=	TARGET= strip

# build rule for common source above
%.o: ../%.c
		$(COMPILE.c) $<

.KEEP_STATE:

.PARALLEL: $(COMMONOBJS) $(OBJS)

all :		$(PROG) $(SUBDIRS)

$(PROG) :	$(OBJS) $(COMMONOBJS)
		$(LINK.c) -o $@ $(OBJS) $(COMMONOBJS) $(LDLIBS)
		$(POST_PROCESS)

install :	$(PROG) $(ROOTPROG) $(SUBDIRS)

catalog:        $(POFILE)
 
$(POFILE):      $(POFILES)
	 $(RM)	$@
	 cat $(POFILES)  >       $@


clean :		$(SUBDIRS)
		$(RM) $(OBJS) $(COMMONOBJS)

strip :
		$(STRIP) $(PROG)

lint :		lint_SRCS

include		../../Makefile.targ

# additional dependency for clobber which is defined in Makefile.targ
clobber :	$(SUBDIRS)

$(SUBDIRS) :	FRC
		@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
