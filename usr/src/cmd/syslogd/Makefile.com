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
# Copyright (c) 2018, Joyent, Inc.

PROG= 		syslogd
ROTATESCRIPT=	newsyslog
CONFIGFILE=	syslog.conf
TXTS= 		syslog.conf
PRODUCT=	$(PROG) $(ROTATESCRIPT)
OBJS=		syslogd.o queue.o list.o conf.o
SRCS=		$(OBJS:%.o=../%.c)
LLOBJS=		$(OBJS:%.o=%.ll)

include ../../Makefile.cmd

$(PROG) lint 	:= LDLIBS += -lscf -lnsl
CERRWARN	+= $(CNOWARN_UNINIT)

# not linted
SMATCH=off

CPPFLAGS	+= -D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT
CFLAGS		+= -DNDEBUG

# there's some extra utility code defined but not used.
LINTFLAGS	+= -erroff=E_NAME_DEF_NOT_USED2

VARSYSLOG=	syslog
VARAUTHLOG=	authlog
ROOTVARLOGD=	$(ROOT)/var/log

ROOTETCCONFIG=	$(CONFIGFILE:%=$(ROOTETC)/%)
ROOTLIBROTATE=	$(ROTATESCRIPT:%=$(ROOTLIB)/%)
ROOTVARSYSLOG=	$(VARSYSLOG:%=$(ROOTVARLOGD)/%)
ROOTVARAUTHLOG=	$(VARAUTHLOG:%=$(ROOTVARLOGD)/%)

$(ROOTUSRSBINPROG) 	:= FILEMODE = 0555
$(ROOTUSRLIBROTATE)	:= FILEMODE = 0555
$(ROOTETCCONFIG)	:= FILEMODE = 0644
$(ROOTVARSYSLOG)	:= FILEMODE = 0644
$(ROOTVARAUTHLOG)	:= FILEMODE = 0600

$(ROOTVARLOGD)/% : %
	$(INS.file)

$(ROOTETC)/%:	../%
	$(INS.file)

$(ROOTLIB)/%:	../%
	$(INS.file)

.KEEP_STATE:

.SUFFIXES:	$(SUFFIXES) .ll

.c.ll:
	$(CC) $(CFLAGS) $(CPPFLAGS) -Zll -o $@ $<

.PARALLEL: $(OBJS)


$(VARSYSLOG) $(VARAUTHLOG):
	$(ECHO) '\c' > $@

%.o: ../%.c
	$(COMPILE.c) $<

%.ll: ../%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -Zll -o $@ $<

syslogd: $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

logfiles: $(ROOTVARSYSLOG) $(ROOTVARAUTHLOG)

clean:
	$(RM) $(OBJS) $(LLOBJS) $(VARSYSLOG) $(VARAUTHLOG)

lint:	lint_SRCS

lock_lint:	$(LLOBJS)

include ../../Makefile.targ
