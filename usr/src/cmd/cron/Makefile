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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include		../Makefile.cmd

MANIFEST =	cron.xml

ROOTMANIFESTDIR = $(ROOTSVCSYSTEM)
ROOTMETHOD =	$(ROOTLIBSVCMETHOD)/svc-cron

CPPFLAGS +=	-D_FILE_OFFSET_BITS=64

ROOTVAR =	$(ROOT)/var

ROOTSPCRON =	$(ROOTVAR)/spool/cron
ROOTCROND =	$(ROOTETC)/cron.d
ROOTDEFAULT =	$(ROOTETC)/default
ROOTCRONTABS =	$(ROOTSPCRON)/crontabs
ROOTATJOBS =	$(ROOTSPCRON)/atjobs
ROOTLIBCRON =	$(ROOTLIB)/cron

PROG1 =		cron
PROG2 =		at atq atrm crontab
XPG4PROG =	at
PROG =		$(PROG1) $(PROG2)

SCRIPT =	batch
XPG4SCRIPT =	batch.xpg4

FILES =		cron.dfl

POFILE=		$(PROG1)_cmd.po
POFILES=	at.po crontab.po funcs.po batch.po
XGETFLAGS=	-a -x $(PROG1).xcl

ROOTDIRS =	$(ROOTSPCRON) $(ROOTCROND) $(ROOTDEFAULT)	\
		$(ROOTCRONTABS) $(ROOTATJOBS)

ROOTPROG =	$(PROG1:%=$(ROOTUSRSBIN)/%) $(PROG2:%=$(ROOTBIN)/%)	\
		$(SCRIPT:%=$(ROOTBIN)/%) $(FILES:%=$(ROOTDEFAULT)/%)	\
		$(XPG4PROG:%=$(ROOTXPG4BIN)/%) \
		$(XPG4SCRIPT:%.xpg4=$(ROOTXPG4BIN)/%)

ROOTSETUP =	$(ROOTDEFAULT)/cron

ROOTSYMLINK =	$(ROOTLIBCRON) $(ROOTETC)/cron

COMMONOBJ1=	permit.o
COMMONOBJ2=	funcs.o
COMMONOBJS=	$(COMMONOBJ1) $(COMMONOBJ2)
CRONOBJS=	cron.o elm.o
ATOBJS=		at.o att1.o att2.o
XPG4OBJS=	values-xpg4.o
ATRMOBJS=	atrm.o
ATQOBJS=	atq.o
CRONTABOBJS=	crontab.o

XPG4ATOBJS=	$(ATOBJS:%=atobjs.xpg4/%) $(COMMONOBJS:%=atobjs.xpg4/%) \
		$(XPG4OBJS:%=atobjs.xpg4/%)

cron :=		POBJS = $(CRONOBJS) $(COMMONOBJ2)
at :=		POBJS = $(ATOBJS) $(COMMONOBJS)
at.xpg4 :=	POBJS = $(XPG4ATOBJS)
atrm :=		POBJS = $(ATRMOBJS) $(COMMONOBJS)
atq :=		POBJS = $(ATQOBJS) $(COMMONOBJS)
crontab :=	POBJS = crontab.o $(COMMONOBJS)

at.o atobjs.xpg4/at.o funcs.o permit.o crontab.o elm.o := CFLAGS += $(CCVERBOSE)

XPG4POBJS =	atobjs.xpg4/at.o atobjs.xpg4/att1.o		\
		atobjs.xpg4/att2.o atobjs.xpg4/funcs.o			\
		atobjs.xpg4/permit.o atobjs.xpg4/values-xpg4.o
NOBJS=		$(CRONOBJS) $(ATOBJS) $(ATRMOBJS) $(ATQOBJS) $(CRONTABOBJS) \
		$(COMMONOBJS)
OBJS =		$(NOBJS) $(XPG4ATOBJS)
SRCS =		$(NOBJS:%.o=%.c)

CLOBBERFILES +=	$(SCRIPT) $(XPG4SCRIPT)

$(ROOTLIBCRON) :=		SYMLNKDEST = ../../etc/cron.d
$(ROOTETC)/cron :=		SYMLNKDEST = ../usr/sbin/cron

$(ROOTBIN)/at :=		FILEMODE = 04755
$(ROOTBIN)/at :=		OWNER = root   
$(ROOTBIN)/at :=		GROUP = sys
$(ROOTXPG4BIN)/at :=		FILEMODE = 04755
$(ROOTXPG4BIN)/at :=		OWNER = root
$(ROOTXPG4BIN)/at :=		GROUP = sys
$(ROOTBIN)/atrm :=		FILEMODE = 04755
$(ROOTBIN)/atrm :=		OWNER = root   
$(ROOTBIN)/atrm :=		GROUP = sys
$(ROOTBIN)/atq :=		FILEMODE = 04755
$(ROOTBIN)/atq :=		OWNER = root   
$(ROOTBIN)/atq :=		GROUP = sys
$(ROOTBIN)/crontab :=		FILEMODE = 04555
$(ROOTBIN)/crontab :=		OWNER = root
$(ROOTUSRSBIN)/cron :=		FILEMODE = 0555
$(ROOTUSRSBIN)/cron :=		OWNER = root
$(ROOTUSRSBIN)/cron :=		GROUP = sys

LDLIBS +=	-lbsm

at :=		LDLIBS += -lproject -lsecdb
at.xpg4 :=	LDLIBS += -lproject -lsecdb
atq :=		LDLIBS += -lsecdb
atrm :=		LDLIBS += -lsecdb
cron :=		LDLIBS += -lcmd -lpam -lproject -lcontract
crontab :=	LDLIBS += -lsecdb -lpam

lint :=		LDLIBS += -lproject -lsecdb -lcontract -lpam

$(XPG4) := CFLAGS += -DXPG4

$(ROOTSVCSYSTEM)/cron.xml := OWNER = root
$(ROOTSVCSYSTEM)/cron.xml := GROUP = sys
$(ROOTSVCSYSTEM)/cron.xml := FILEMODE = 0444

$(ROOTLIBSVCMETHOD)/svc-cron := OWNER = root
$(ROOTLIBSVCMETHOD)/svc-cron := GROUP = bin
$(ROOTLIBSVCMETHOD)/svc-cron := FILEMODE = 0555


.KEEP_STATE:

all :		$(PROG) $(XPG4) $(SCRIPT) $(XPG4SCRIPT) $(FILES)

install :	all $(ROOTPROG) $(ROOTSETUP) $(ROOTSYMLINK) \
		$(ROOTMANIFEST) $(ROOTMETHOD)

$(PROG) :	$$(POBJS)
		$(LINK.c) $(POBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

$(XPG4) :	atobjs.xpg4 $(XPG4POBJS)
		$(LINK.c) $(XPG4POBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

atobjs.xpg4/%.o:	%.c
	$(COMPILE.c) -o $@ $<

atobjs.xpg4:
	-@mkdir -p $@

atobjs.xpg4/values-xpg4.o:	../../lib/common/common/values-xpg4.c
	$(COMPILE.c) -o $@ ../../lib/common/common/values-xpg4.c

att1.c :	att1.y
		$(YACC.y) -d att1.y
		$(MV) y.tab.c att1.c
		$(MV) y.tab.h att1.h

att2.c :	att2.l att2.ed att1.c
		$(LEX) att2.l
		ed - lex.yy.c < att2.ed
		$(MV) lex.yy.c att2.c

# Don't re-install direcories installed by Targetdirs
#$(ROOTDIRS):
#		$(INS.dir)

$(ROOTCROND)/% $(ROOTDEFAULT)/% : %
		$(INS.file)

$(ROOTSYMLINK) :
		$(RM) $@; $(SYMLINK) $(SYMLNKDEST) $@

$(ROOTSETUP) :	$(ROOTDEFAULT)/cron.dfl
		$(RM) $@; $(MV) $(ROOTDEFAULT)/cron.dfl $@

check:		$(CHKMANIFEST)

$(POFILE):	$(POFILES)
	$(RM) $@; cat $(POFILES) > $@

clean :
		$(RM) $(OBJS) att1.h att1.c att2.c

lint :		lint_SRCS

strip :
		$(STRIP) $(PROG) $(XPG4)

include		../Makefile.targ
