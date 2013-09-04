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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/bnu/Makefile
#

MANIFEST =	uucp.xml

include		../Makefile.cmd

USERPROG1 =	uudecode uuencode
USERPROG =	$(USERPROG1) uucp uuglist uuname uustat uux ct cu
UUCPPROG1 =	bnuconvert uucheck uucleanup
UUCPPROG =	$(UUCPPROG1) remote.unknown uusched uucico uuxqt
SBINPROG =	in.uucpd

PROG =		$(UUCPPROG) $(USERPROG) $(SBINPROG)

LIBSHELLS =	Uutry uudemon.admin uudemon.cleanup uudemon.hour uudemon.poll
BINSHELLS =	uulog uupick uuto
SHELLS =	$(LIBSHELLS) $(BINSHELLS)
CRONTAB =	uudemon.crontab

#include	../../lib/Makefile.lib

FILES =		Config Devconfig Devices Dialcodes	\
		Dialers Grades Limits Permissions	\
		Poll Sysfiles Systems

CLEANFILES =	$(SRCS:%.c=%.o) common.o

# This Makefile overrides the standard POFILES (*.cat)
# so we have to augment clobber this ugly way.
CLOBBERFILES +=	$(SRCS:%.c=%.po) common.po

TXTFILES =	README $(FILES)	\
		dkbreak.c dkdial.c dkerr.c dkminor.c dtnamer.c	\
		Cvt Install SetUp Teardown dial.c dial.h getopt.c strpbrk.c

ROOTMANIFESTDIR=	$(ROOTSVCNETWORK)

CAT =		cat
POFILE =	bnu.po
# step around name collisions
POFILES =	$(PROG:%=%.cat)

CPPFLAGS =	-I. $(SMALLFLAG) $(CPPFLAGS.master) # -DSMALL

FILEMODE =	4511

# if you change these directories, change them in uucp.h as well

ROOTLIBUUCP =	$(ROOT)/usr/lib/uucp
ROOTETCUUCP =	$(ROOT)/etc/uucp
ROOTVAR =	$(ROOT)/var
ROOTVARUUCP =	$(ROOTVAR)/uucp
ROOTSPOOL =	$(ROOTVAR)/spool
ROOTSPLOCKS =	$(ROOTSPOOL)/locks
ROOTSPUUCP =	$(ROOTSPOOL)/uucp
ROOTSPPUB =	$(ROOTSPOOL)/uucppublic

DOTADMIN =	.Admin
DOTCORRUPT =	.Corrupt
DOTLOG =	.Log
DOTOLD =	.Old
DOTSEQ =	.Sequence
DOTSTATUS =	.Status
DOTWORKSPACE =	.Workspace
DOTXQT =	.Xqtdir
DOTDIRS =	$(DOTADMIN) $(DOTLOG) $(DOTOLD) $(DOTSEQ) $(DOTSTATUS)
DOTSPDIRS =	$(DOTCORRUPT) $(DOTWORKSPACE) $(DOTXQT)

DOTLOGCICO =	$(DOTLOG)/uucico
DOTLOGUUCP =	$(DOTLOG)/uucp
DOTLOGUUX =	$(DOTLOG)/uux
DOTLOGUUXQT =	$(DOTLOG)/uuxqt
DOTLOGDIRS =	$(DOTLOGCICO) $(DOTLOGUUCP) $(DOTLOGUUX) $(DOTLOGUUXQT)

ROOTDOTDIRS =	$(DOTDIRS:%=$(ROOTVARUUCP)/%)
ROOTDOTSPDIRS =	$(DOTSPDIRS:%=$(ROOTSPUUCP)/%)
ROOTDOTLOGDIRS = $(DOTLOGDIRS:%=$(ROOTVARUUCP)/%)

ROOTPROG =	$(USERPROG:%=$(ROOTBIN)/%)
ROOTSPROG =	$(SBINPROG:%=$(ROOTUSRSBIN)/%)
ROOTSHELLS =	$(BINSHELLS:%=$(ROOTBIN)/%)
ROOTUUCPPROG =	$(UUCPPROG:%=$(ROOTLIBUUCP)/%)
ROOTLIBSHELLS =	$(LIBSHELLS:%=$(ROOTLIBUUCP)/%)
ROOTCRONTAB =	$(CRONTAB:%=$(ROOTLIBUUCP)/%)
ROOTFILES =	$(FILES:%=$(ROOTETCUUCP)/%)

ROOTDIRS =	$(ROOTLIBUUCP) $(ROOTETCUUCP) $(ROOTSPLOCKS)	\
		$(ROOTDOTDIRS) $(ROOTDOTSPDIRS) $(ROOTDOTLOGDIRS)

ROOTSYMDIRS =	$(DOTDIRS:%=$(ROOTSPUUCP)/%)
SYMDEST =	../../uucp
ROOTREMOTE =	$(ROOTETCUUCP)/remote.unknown
REMOTESYMDEST =	../../usr/lib/uucp

$(USERPROG1) := CPPFLAGS += -D_FILE_OFFSET_BITS=64

# Mode is assigned in Targetdirs.  It shoudn't be re-assigned here
$(USERPROG1:%=$(ROOTBIN)/%) :=		FILEMODE = 0555
$(ROOTSHELLS) :=			FILEMODE = 0555
$(ROOTLIBSHELLS) :=			FILEMODE = 0555
$(UUCPPROG1:%=$(ROOTLIBUUCP)/%) :=	FILEMODE = 0510
$(ROOTCRONTAB) :=			FILEMODE = 0444
$(ROOTFILES) :=				FILEMODE = 0644
$(ROOTETCUUCP)/Permissions :=		FILEMODE = 0600
$(ROOTETCUUCP)/Systems :=		FILEMODE = 0600
$(ROOTSPROG) :=				FILEMODE = 0555

include		./Makefile.inc

.KEEP_STATE:

all:		$(TXTFILES) $(PROG) $(SHELLS)

install:	$(ROOTDIRS) $(ROOTSYMDIRS) $(ROOTPROG)		\
		$(ROOTUUCPPROG) $(ROOTLIBSHELLS) $(ROOTSHELLS)	\
		$(ROOTFILES) $(ROOTSYMFILES) $(ROOTSPROG)	\
		$(ROOTREMOTE) $(ROOTCRONTAB) $(ROOTMANIFEST)

$(ROOTLIBUUCP)/% $(ROOTETCUUCP)/% $(ROOTUSRSBIN)/%: %
		$(INS.file)

$(PROG):	$$(POBJS)
		$(LINK.c) $(POBJS) -o $@ $(LDLIBS) $(PLIBS)
		$(POST_PROCESS)

$(POFILE):	$(POFILES)
		$(RM) $@; $(CAT) $(POFILES) > $@

$(POFILES):	$$(POBJS:.o=.po)
		$(RM) $@; $(CAT) $(POBJS:.o=.po) > $@

$(ROOTDIRS):
		$(INS.dir)

$(ROOTSYMDIRS):
		$(RM) $@; $(SYMLINK) $(SYMDEST)/$(@F) $@

$(ROOTREMOTE):
		$(RM) $@; $(SYMLINK) $(REMOTESYMDEST)/$(@F) $@

check:		$(CHKMANIFEST)

clean:
		$(RM) $(CLEANFILES)

lint:		lint_SRCS

strip:
		$(STRIP) $(PROG)

# special rules for 'common', since it lives in chmod's directory

common.o:	../chmod/common.c
		$(COMPILE.c) -o $@ ../chmod/common.c

common.po:	../chmod/common.c
		$(COMPILE.cpp) ../chmod/common.c > common.c.i
		$(XGETTEXT) $(XGETFLAGS) common.c.i ;\
		$(RM)   $@ ;\
		sed "/^domain/d" < messages.po  > $@ ;\
		$(RM) messages.po common.c.i

include		../Makefile.targ
