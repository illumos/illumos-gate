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
# Copyright 2020 Joyent, Inc.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.

DEFAULTFILES =	cron.dfl

include		../Makefile.cmd

MANIFEST =	cron.xml

ROOTMANIFESTDIR = $(ROOTSVCSYSTEM)
ROOTMETHOD =	$(ROOTLIBSVCMETHOD)/svc-cron

CPPFLAGS +=	-D_FILE_OFFSET_BITS=64 -I $(SRC)/common/util
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	$(CNOWARN_UNINIT)
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-unused-value

SMOFF +=	signed_integer_overflow_check,all_func_returns

ROOTVAR =	$(ROOT)/var

ROOTSPCRON =	$(ROOTVAR)/spool/cron
ROOTCROND =	$(ROOTETC)/cron.d
ROOTCRONTABS =	$(ROOTSPCRON)/crontabs
ROOTATJOBS =	$(ROOTSPCRON)/atjobs
ROOTLIBCRON =	$(ROOTLIB)/cron

PROG1 =		cron
PROG2 =		at atq atrm crontab
XPG6PROG =	crontab
XPG4PROG =	at crontab
PROG =		$(PROG1) $(PROG2)
PARSETEST =	parsetest

SCRIPT =	batch
XPG4SCRIPT =	batch.xpg4

POFILE=		$(PROG1)_cmd.po
POFILES1=	at.po crontab.po funcs.po batch.po
POFILES=	$(POFILES1) atrm.po
$(POFILES1) :=	XGETFLAGS= -a -x $(PROG1).xcl

ROOTDIRS =	$(ROOTSPCRON) $(ROOTCROND) \
		$(ROOTCRONTABS) $(ROOTATJOBS)

ROOTPROG =	$(PROG1:%=$(ROOTUSRSBIN)/%) $(PROG2:%=$(ROOTBIN)/%)	\
		$(SCRIPT:%=$(ROOTBIN)/%) \
		$(XPG6PROG:%=$(ROOTXPG6BIN)/%) \
		$(XPG4PROG:%=$(ROOTXPG4BIN)/%) \
		$(XPG4SCRIPT:%.xpg4=$(ROOTXPG4BIN)/%)

ROOTSYMLINK =	$(ROOTLIBCRON) $(ROOTETC)/cron

GETRESPSRC=	$(SRC)/common/util/getresponse.c
GETRESPOBJ=	getresponse.o
COMMONOBJ1=	permit.o
COMMONOBJ2=	funcs.o
COMMONOBJS=	$(COMMONOBJ1) $(COMMONOBJ2)
CRONOBJS=	cron.o elm.o parse.o
ATOBJS=		at.o att1.o att2.o
XPG4OBJS=	values-xpg4.o
ATRMOBJS1=	atrm.o
ATRMOBJS=	$(ATRMOBJS1) $(GETRESPOBJ)
ATQOBJS=	atq.o
CRONTABOBJS1=	crontab.o parse.o
CRONTABOBJS=	$(CRONTABOBJS1) $(GETRESPOBJ)
PARSETESTOBJS=	parse.o

# /usr/xpg*/bin/crontab isn't linked with values-xpg*.o since it isn't
# required by any specific behavior differences; this makes these
# setuid variants less likely to accidently trip over differences that
# could unintentionally open up a security hole.
XPG4COMMONOBJS=	$(COMMONOBJS:%=objs.xpg4/%)
XPG4CTOBJS=	$(CRONTABOBJS:%=objs.xpg4/%)
XPG4ATOBJS=	$(ATOBJS:%=objs.xpg4/%) $(XPG4OBJS:%=objs.xpg4/%)
XPG6COMMONOBJS=	$(COMMONOBJS:%=objs.xpg6/%)
XPG6CTOBJS=	$(CRONTABOBJS:%=objs.xpg6/%)

cron :=		POBJS = $(CRONOBJS) $(COMMONOBJ2)
at :=		POBJS = $(ATOBJS) $(COMMONOBJS)
at.xpg4 :=	POBJS = $(XPG4ATOBJS) $(XPG4COMMONOBJS)
atrm :=		POBJS = $(ATRMOBJS) $(COMMONOBJS)
atq :=		POBJS = $(ATQOBJS) $(COMMONOBJS)
crontab :=	POBJS = $(CRONTABOBJS) $(COMMONOBJS)
crontab.xpg4 :=	POBJS = $(XPG4CTOBJS) $(XPG4COMMONOBJS)
crontab.xpg6 :=	POBJS = $(XPG6CTOBJS) $(XPG6COMMONOBJS)
parsetest :=	POBJS = $(PARSETESTOBJS)

CFLAGS += $(CCVERBOSE)

NOBJS=		$(CRONOBJS) $(ATOBJS) $(ATRMOBJS1) $(ATQOBJS) $(CRONTABOBJS1) \
		$(COMMONOBJS)
OBJS =		$(NOBJS) $(XPG4COMMONOBJS) $(XPG4ATOBJS) $(XPG4CTOBJS) \
		$(XPG6COMMONOBJS) $(XPG6CTOBJS) $(GETRESPOBJ)

SRCS =		$(NOBJS:%.o=%.c) $(GETRESPSRC)

CLOBBERFILES +=	$(SCRIPT) $(XPG4SCRIPT)

$(ROOTLIBCRON) :=		SYMLNKDEST = ../../etc/cron.d
$(ROOTETC)/cron :=		SYMLNKDEST = ../usr/sbin/cron

$(ROOTBIN)/at :=		FILEMODE = 04755
$(ROOTXPG4BIN)/at :=		FILEMODE = 04755
$(ROOTBIN)/atrm :=		FILEMODE = 04755
$(ROOTBIN)/atq :=		FILEMODE = 04755
$(ROOTBIN)/crontab :=		FILEMODE = 04555
$(ROOTXPG6BIN)/crontab :=	FILEMODE = 04555
$(ROOTXPG4BIN)/crontab :=	FILEMODE = 04555
$(ROOTUSRSBIN)/cron :=		FILEMODE = 0555

at :=		LDLIBS += -lbsm -lproject -lsecdb
at.xpg4 :=	LDLIBS += -lbsm -lproject -lsecdb
atq :=		LDLIBS += -lbsm -lsecdb
atrm :=		LDLIBS += -lbsm -lsecdb
cron :=		LDLIBS += -lbsm -lpam -lproject -lcontract -lzoneinfo -lcustr
crontab :=	LDLIBS += -lbsm -lsecdb -lpam -lzoneinfo -lcustr
crontab.xpg6 :=	LDLIBS += -lbsm -lsecdb -lpam -lzoneinfo -lcustr
crontab.xpg4 :=	LDLIBS += -lbsm -lsecdb -lpam -lzoneinfo -lcustr
parsetest :=	LDLIBS += -lcustr

$(XPG4) :=	CFLAGS += -DXPG4
$(XPG6) :=	CFLAGS += -DXPG6
parsetest :=	CFLAGS += -DPARSETEST

$(ROOTSVCSYSTEM)/cron.xml := FILEMODE = 0444
$(ROOTLIBSVCMETHOD)/svc-cron := FILEMODE = 0555

# because of labels from yacc
att1.o := CERRWARN += -_gcc=-Wno-unused-label
att2.o := CERRWARN += -_gcc=-Wno-unused-label
objs.xpg4/att1.o := CERRWARN += -_gcc=-Wno-unused-label
objs.xpg4/att2.o := CERRWARN += -_gcc=-Wno-unused-label
objs.xpg6/att1.o := CERRWARN += -_gcc=-Wno-unused-label
objs.xpg6/att2.o := CERRWARN += -_gcc=-Wno-unused-label

.KEEP_STATE:

all :		$(PROG) $(XPG4) $(XPG6) $(SCRIPT) $(XPG4SCRIPT) $(FILES) \
		$(PARSETEST)

install :	all $(ROOTPROG) $(ROOTETCDEFAULTFILES) $(ROOTSYMLINK) \
		$(ROOTMANIFEST) $(ROOTMETHOD)

$(PROG) $(PARSETEST):	$$(POBJS)
		$(LINK.c) $(POBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

$(XPG4) :	objs.xpg4 $$(POBJS)
		$(LINK.c) $(POBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

$(XPG6) :	objs.xpg6 $$(POBJS)
		$(LINK.c) $(POBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

objs.xpg6/%.o:		%.c
	$(COMPILE.c) -o $@ $<

objs.xpg6:
	-@mkdir -p $@

objs.xpg4/%.o:		%.c
	$(COMPILE.c) -o $@ $<

objs.xpg4:
	-@mkdir -p $@

objs.xpg4/values-xpg4.o:	../../lib/crt/common/values-xpg4.c
	$(COMPILE.c) -o $@ ../../lib/crt/common/values-xpg4.c

%.o:			$(SRC)/common/util/%.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POST_PROCESS_O)

objs.xpg4/%.o:	$(SRC)/common/util/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

objs.xpg6/%.o:	$(SRC)/common/util/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

att1.c :	att1.y
		$(YACC.y) -d att1.y
		$(MV) y.tab.c att1.c
		$(MV) y.tab.h att1.h

att2.c :	att2.l att2.ed att1.c
		$(LEX) att2.l
		ed - lex.yy.c < att2.ed
		$(MV) lex.yy.c att2.c

# Don't re-install directories installed by Targetdirs
#$(ROOTDIRS):
#		$(INS.dir)

$(ROOTSYMLINK) :
		$(RM) $@; $(SYMLINK) $(SYMLNKDEST) $@

check:		$(CHKMANIFEST)

$(POFILE):	$(POFILES)
	$(RM) $@; cat $(POFILES) > $@

clean :
		$(RM) $(OBJS) att1.h att1.c att2.c

strip :
		$(STRIP) $(PROG) $(XPG4) $(XPG6)

include		../Makefile.targ
