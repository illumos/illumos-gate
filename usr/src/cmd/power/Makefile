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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/power/Makefile
#
#

DAEMON_SRCS =	powerd.c sysstat.c
DAEMON_OBJS =	$(DAEMON_SRCS:%.c=%.o)
DAEMON =	powerd
PMCFG_SRCS = 	conf.c parse.c handlers.c
PMCFG_OBJS =	$(PMCFG_SRCS:%.c=%.o)
PMCFG = 	pmconfig
SRCS = 		$(DAEMON_SRCS) $(PMCFG_SRCS)
OBJS = 		$(SRCS:%.c=%.o)
SCRIPTS =	sysidpm.sh
SYSIDPM = 	sysidpm
PROG =		$(DAEMON) $(PMCFG) $(SYSIDPM)
ETCFILES =	power.conf
POWERPERM =	power

include ../Makefile.cmd

MANIFEST =	power.xml

ROOTMANIFESTDIR =	$(ROOTSVCSYSTEM)
ROOTMETHOD =	$(ROOTLIBSVCMETHOD)/svc-power

TEXT_DOMAIN=	SUNW_OST_OSCMD

POFILE=		power_all.po
POFILES=	$(PMCFG_SRCS:%.c=%.po)
# needed because POFILES is deleted by clobber, but it's under
# SCCS control here.
OPOFILES=	sysidpm.po

#
# we only need libdevinfo on sparc
sparc_LDEVINFO=	-ldevinfo
i386_LDEVINFO=

DAEMON_LDLIBS =	$(LDLIBS.cmd) -lkstat $($(MACH)_LDEVINFO)
PMCFG_LDLIBS =	$(LDLIBS.cmd) -lcmd $($(MACH)_LDEVINFO)

OWNER= root
ROOTUSRSBINPMCFG= $(PMCFG:%=$(ROOTUSRSBIN)/%)
$(ROOTUSRSBINPMCFG) := GROUP= bin
$(ROOTUSRSBINPMCFG) := FILEMODE= 4555

GROUP= sys
ROOTLIBPOWER= $(ROOTLIB)/power
ROOTLIBPOWERDAEMON= $(DAEMON:%=$(ROOTLIBPOWER)/%)
$(ROOTLIBPOWER) := GROUP= sys
$(ROOTLIBPOWER) := FILEMODE= 755
$(ROOTLIBPOWERDAEMON) := GROUP= bin
$(ROOTLIBPOWERDAEMON) := FILEMODE= 555

ROOTETCFILES= $(ETCFILES:%=$(ROOTETC)/%)
$(ROOTETCFILES) := FILEMODE= 644

DFLTD= $(ROOTETC)/default
ROOTDFLFILES= $(POWERPERM:%=$(DFLTD)/%)
$(ROOTDFLFILES) := FILEMODE= 444

ROOTUSRSBINSYSIDPM= $(SYSIDPM:%=$(ROOTUSRSBIN)/%)
$(ROOTUSRSBINSYSIDPM) := FILEMODE= 755

#
# lint pass one enforcement
#
CFLAGS += $(CCVERBOSE)

.PARALLEL: $(OBJS)

.KEEP_STATE:

all: $(PROG) $(POWERPERM).dfl $(ETCFILES) $(SCRIPTS)

install clean:

$(DAEMON_OBJS): $(DAEMON_SRCS)
	$(CC) $(CFLAGS) -D_REENTRANT $(CPPFLAGS) -o $@ -c $<
	$(PROCESS_COMMENT) $@

$(DAEMON): $(DAEMON_OBJS)
	$(CC) -o $@ $(DAEMON_OBJS) $(LDFLAGS) $(DAEMON_LDLIBS)
	$(POST_PROCESS)

$(PMCFG_OBJS): pmconfig.h

$(PMCFG): $(PMCFG_OBJS)
	$(LINK.c) -o $@ $(PMCFG_OBJS) $(PMCFG_LDLIBS)
	$(POST_PROCESS)
$(ROOTSVCSYSTEM)/power.xml := OWNER = root
$(ROOTSVCSYSTEM)/power.xml := GROUP = sys
$(ROOTSVCSYSTEM)/power.xml := FILEMODE = 0444

$(ROOTLIBSVCMETHOD)/svc-power := OWNER = root
$(ROOTLIBSVCMETHOD)/svc-power := GROUP = bin
$(ROOTLIBSVCMETHOD)/svc-power := FILEMODE = 0555

install: all $(ROOTUSRSBINPMCFG) $(ROOTLIBPOWERDAEMON) \
	$(ROOTETCFILES) $(ROOTUSRSBINSYSIDPM) $(ROOTDFLFILES) \
	$(ROOTMANIFEST) $(ROOTMETHOD)

$(DFLTD)/%:	%.dfl
	$(INS.rename)

$(ROOTLIBPOWER):
	$(INS.dir)

$(ROOTLIBPOWER)/%:	%
	$(INS.file)

$(ROOTLIBPOWERDAEMON): $(ROOTLIBPOWER)

$(OPOFILES):
	@

$(POFILE):	$(POFILES) $(OPOFILES)
	$(RM)	$@
	cat	$(POFILES) $(OPOFILES)	> $@

check:	$(CHKMANIFEST)

clean:
	$(RM) $(OBJS) $(SYSIDPM)
	$(RM) $(POFILE) $(POFILES)

lint := LINTFLAGS=-auxn
lint:
	$(LINT.c) $(DAEMON_SRCS)
	$(LINT.c) $(PMCFG_SRCS)

cstyle:
	$(CSTYLE) $(SRCS)

include ../Makefile.targ
