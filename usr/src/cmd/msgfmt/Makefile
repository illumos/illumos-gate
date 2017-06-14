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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#       Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
#         All Rights Reserved
#
# Copyright 2017 Joyent, Inc.
#

# cmd/msgfmt/Makefile

include ../Makefile.cmd

XOBJS=	xgettext.o

LXOBJS=	xgettext.lx.o

GOBJS=	gnu_msgfmt.o gnu_handle.o gnu_lex.o gnu_hash.o gnu_check.o

YOBJS=	gnu_po.o

BOBJS=	gnu_msgs.o

LOBJS=	gnu_msgs_rev.o

SOBJS=	msgfmt.o check_header.o

COBJS=	option.o util.o

BINPROG= msgfmt xgettext
LIBPROG= gmsgfmt
PROG=  $(BINPROG) $(LIBPROG)

YFLAGS += -d
LINTFLAGS +=	-um

POFILE= msgfmt_all.po
POFILES= $(SOBJS:%.o=%.po) $(GOBJS:%.o=%.po) $(COBJS:%.o=%.po) \
	$(BOBJS:%.o=%.po) $(YOBJS:%.o=%.po)

CLOBBERFILES += gmsgfmt_rev

ROOTBINPROG= $(BINPROG:%=$(ROOTBIN)/%)
ROOTLIBPROG= $(LIBPROG:%=$(ROOTLIB)/%)

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-unused-label
CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-unused-variable

.KEEP_STATE:

.PARALLEL:	$(SOBJS) $(GOBJS) $(YOBJS) $(COBJS) $(BOBJS) $(LOBJS) \
		$(XOBJS) $(LXOBJS)

all: $(PROG) gmsgfmt_rev

msgfmt:	$(SOBJS) $(COBJS)
	$(LINK.c) $(SOBJS) $(COBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

gmsgfmt:	$(GOBJS) $(YOBJS) $(BOBJS) $(COBJS)
	$(LINK.c) $(GOBJS) $(YOBJS) $(BOBJS) $(COBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

gmsgfmt_rev:	$(GOBJS) $(YOBJS) $(LOBJS) $(COBJS)
	$(LINK.c) $(GOBJS) $(YOBJS) $(LOBJS) $(COBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

xgettext: $(XOBJS) $(LXOBJS)
	$(LINK.c) $(XOBJS) $(LXOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(POFILES): y.tab.h

$(POFILE):	$(POFILES)
	$(RM) $@
	cat $(POFILES) > $@

install: all $(ROOTBINPROG) $(ROOTLIBPROG)

clean:  
	$(RM) $(SOBJS) $(GOBJS) $(YOBJS) $(COBJS) \
		$(XOBJS) $(LXOBJS) $(BOBJS) $(LOBJS) \
		$(POFILE) $(POFILES) gnu_po.c y.tab.h xgettext.lx.c

lint:	gnu_po.c y.tab.h
	$(LINT.c) $(SOBJS:%.o=%.c) $(COBJS:%.o=%.c) $(LDLIBS)
	$(LINT.c) $(GOBJS:%.o=%.c) $(BOBJS:%.o=%.c) $(COBJS:%.o=%.c) $(LDLIBS)
	$(LINT.c) $(GOBJS:%.o=%.c) $(LOBJS:%.o=%.c) $(COBJS:%.o=%.c) $(LDLIBS)
	$(LINT.c) $(XOBJS:%.o=%.c) $(LDLIBS)

gnu_po.c + y.tab.h:	gnu_po.y
	$(RM) gnu_po.c y.tab.h
	$(YACC.y) gnu_po.y
	mv y.tab.c gnu_po.c

gnu_lex.o:	y.tab.h

include ../Makefile.targ
