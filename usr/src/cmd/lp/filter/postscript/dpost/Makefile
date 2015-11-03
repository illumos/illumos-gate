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
# Copyright 2015 Igor Kozhukhov <ikozhukhov@gmail.com>
#
# cmd/lp/filter/postscript/dpost/Makefile
#

include         ../../../Makefile.lp

PROG=           dpost

SRCS =		dpost.c draw.c color.c pictures.c ps_include.c

OBJS =		$(SRCS:%.c=%.o)

COMMONDIR=      ../common

COMMONOBJS =	$(COMMONDIR)/glob.o \
		$(COMMONDIR)/misc.o \
		$(COMMONDIR)/request.o \
		$(COMMONDIR)/tempnam.o

TXTS=		README 

# dpost uses some floating point arithmetic, so if you're running on a system
# without floating point hardware add the -f option to the definition of CFLAGS.

ENCODING=	2
CPPFLAGS =	-DDFLTENCODING=$(ENCODING)	\
		-I. -I$(COMMONDIR)		\
		$(CPPFLAGS.master)

POFILE =	lp_filter_postscript_dpost.po

.KEEP_STATE:

all:		$(TXTS) $(PROG)

install:	all $(ROOTLIBLPPOSTPROG)

$(PROG):	$(OBJS) $(COMMONOBJS)
		$(LINK.c) -o $@ $(OBJS) $(COMMONOBJS) $(LDLIBS)
		$(POST_PROCESS)

$(COMMONOBJS):	$$(@:%.o=%.c)
		cd $(@D); $(MAKE) $(@F)

ps_include.o:	ps_include.h
ps_include.h:	ps_include.ps ps_include.awk
		$(RM) $@; $(AWK) -f ps_include.awk ps_include.ps >$@

clean:
		$(RM) $(OBJS) ps_include.h

strip:
		$(STRIP) $(PROG)

lint:		lint_SRCS

include		../../../../Makefile.targ

include		../Makefile.msg
