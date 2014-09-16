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

# Copyright (c) 2011 Gary Mills

#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/sendmail/src/Makefile
#

PROG=	sendmail

include 	../../Makefile.cmd
include 	../Makefile.cmd

OBJS= alias.o arpadate.o bf.o collect.o conf.o control.o convtime.o daemon.o \
	deliver.o domain.o envelope.o err.o headers.o macro.o main.o map.o \
	mci.o milter.o mime.o parseaddr.o queue.o ratectrl.o readcf.o \
	recipient.o sasl.o savemail.o sfsasl.o sm_resolve.o srvrsmtp.o stab.o \
	stats.o sysexits.o tls.o trace.o udb.o usersmtp.o util.o version.o

SRCS=	$(OBJS:%.o=%.c)

MAPFILES =	$(MAPFILE.INT) $(MAPFILE.NGB)
LDFLAGS +=	$(MAPFILES:%=-M%)

LDLIBS += 	../libsmutil/libsmutil.a ../libsm/libsm.a -lresolv -lsocket \
		-lnsl ../db/libdb.a -lldap -lsldap -lwrap -lumem \
		-lssl -lcrypto -lsasl

INCPATH=	-I. -I../include -I../db

ENVDEF=		-DNETINET6 -DTCPWRAPPERS -DSTARTTLS -DSASL=20115
SUNENVDEF=	-DSUN_EXTENSIONS -DVENDOR_DEFAULT=VENDOR_SUN \
		-DSUN_INIT_DOMAIN -DSUN_SIMPLIFIED_LDAP -D_FFR_LOCAL_DAEMON \
		-D_FFR_MAIL_MACRO

CPPFLAGS = 	$(INCPATH) $(ENVDEF) $(SUNENVDEF) $(DBMDEF) $(CPPFLAGS.sm)

FILEMODE= 	2555

ROOTSYMLINKS=	$(ROOTLIBSMTPSM)/newaliases

# build rule
#

.KEEP_STATE:
all:		$(PROG)

.PARALLEL:	$(OBJS)

$(PROG):	$(OBJS) $(MAPFILES) \
	../libsmutil/libsmutil.a ../libsm/libsm.a ../db/libdb.a
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install:	$(ROOTLIBSMTPSM)/sendmail $(ROOTSYMLINKS)

$(ROOTSYMLINKS):
	$(RM) $@; $(SYMLINK) sendmail $@

clean:
	$(RM) $(PROG) $(OBJS)

lint:	lint_SRCS

include		../../Makefile.targ
