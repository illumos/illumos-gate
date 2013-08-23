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
# cmd/mailx/Makefile

PROG= mailx

OBJS=	myfopen.o aux.o cmd1.o cmd2.o cmd3.o \
	cmd4.o cmdtab.o collect.o config.o edit.o \
	init.o fio.o getname.o head.o \
	hostname.o lex.o list.o lock.o lpaths.o \
	main.o names.o optim.o popen.o quit.o \
	receipt.o send.o sigretro.o stralloc.o temp.o \
	translate.o tty.o usg.local.o vars.o

SRCS=	$(OBJS:.o=.c)

MISC= misc

include ../Makefile.cmd
#
# for messaging catalogue file
#
POFILE= mailx.po
POFILES= $(SRCS:%.c=%.po)

ROOTMAILXD=	$(ROOTSHLIB)/mailx
ROOTETCMAILD=	$(ROOTETC)/mail
MAILXHELP=	mailx.help mailx.help.~
ROOTMAILXHELP=	$(MAILXHELP:%=$(ROOTMAILXD)/%)
MAILXRC=	$(MISC)/mailx.rc
UCBMAILRC=	$(MISC)/Mail.rc
ROOTMAILXRC=	$(MAILXRC:$(MISC)/%=$(ROOTETCMAILD)/%)
ROOTUCBMAILRC=	$(UCBMAILRC:$(MISC)/%=$(ROOTETCMAILD)/%)
ROOTUCBMAIL=	$(ROOT)/usr/ucb/mail
ROOTUCBCAPMAIL=	$(ROOT)/usr/ucb/Mail

$(ROOTPROG) :=		FILEMODE =	02511
$(ROOTMAILXHELP) :=	FILEMODE =	0644
$(ROOTMAILXRC) :=	FILEMODE =	0644
$(ROOTUCBMAILRC) :=	FILEMODE =	0644

CPPFLAGS=	-Ihdr -DUSG -DOPTIM $(CPPFLAGS.master)
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-clobbered
LINTFLAGS= 	-hb
LDLIBS +=	-lmail
LDFLAGS +=	$(MAPFILE.NGB:%=-M%)

CLOBBERFILES += $(MAILXHELP)

# install rules
$(ROOTMAILXD)/% : %
	$(INS.file)

$(ROOTETCMAILD)/% : $(MISC)/%
	$(INS.file)

.KEEP_STATE:

all: $(PROG) $(MAILXHELP) $(MAILXRC) $(UCBMAILRC)

$(PROG): $(OBJS) $(LIBMAIL)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTMAILXD) $(ROOTPROG) $(ROOTMAILXHELP) \
	$(ROOTMAILXRC) $(ROOTUCBMAIL) $(ROOTUCBCAPMAIL) $(ROOTUCBMAILRC)

$(ROOTUCBMAIL) $(ROOTUCBCAPMAIL):
	$(RM) $@; $(SYMLINK) ../bin/mailx $@

$(ROOTMAILXD):
	$(INS.dir)

$(MAILXHELP): $(MISC)/$$@
	$(GREP) -v '^#.*@(' $(MISC)/$@ > $@

$(POFILE):      $(POFILES)
	$(RM)	$@
	cat     $(POFILES)      > $@

clean:
	$(RM) $(OBJS)

lint: lint_SRCS

include ../Makefile.targ

FRC:
