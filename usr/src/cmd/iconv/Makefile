#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
# Copyright 2017 Joyent Inc.
#

PROG=iconv

include ../Makefile.cmd
include ../Makefile.ctf

OBJS = iconv_main.o iconv_list.o charmap.o parser.tab.o scanner.o

SRCS	= $(OBJS:%.o=%.c)

CSTD=	$(CSTD_GNU99)
LDLIBS		+= -lcmdutils -lavl
YFLAGS		= -d -b parser
CPPFLAGS	+= -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
$(RELEASE_BUILD) CPPFLAGS += -DNDEBUG

CERRWARN +=	-_gcc=-Wno-unused-label

CLEANFILES	= $(OBJS) parser.tab.c parser.tab.h
CLOBBERFILES	= $(PROG) $(POFILE)
PIFILES		= $(OBJS:%.o=%.i)
POFILE		= iconv_cmd.po

all: $(PROG)

install: all $(ROOTPROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(OBJS):	parser.tab.h
$(PIFILES):	parser.tab.h

parser.tab.c parser.tab.h: parser.y
	$(YACC) $(YFLAGS) parser.y

lint:	$(SRCS)
	$(LINT.c) $(CPPFLAGS) $(SRCS)

clean:
	$(RM) $(CLEANFILES)

$(POFILE):	$(PIFILES)
	$(RM) $@
	$(RM) messages.po
	$(XGETTEXT) -s $(PIFILES)
	$(SED) -e '/domain/d' messages.po > $@
	$(RM) $(PIFILES) messages.po

.KEEP_STATE:

include ../Makefile.targ
