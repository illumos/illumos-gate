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

# cmd/sendmail/aux/Makefile
#
include		../../Makefile.cmd
include		../Makefile.cmd

PROG= 		mailstats mconnect vacation mailcompat praliases

LIBPROG=	mail.local smrsh

USRSBINPROG=	etrn makemap editmap

LIBSMTPSMPROG= mailq

# $(PROG) by default
CLOBBERFILES=	$(LIBPROG) $(USRSBINPROG) $(LIBSMTPSMPROG)

OBJS= 		$(PROG:%=%.o)

.PARALLEL:	$(OBJS) $(PROG) $(LIBPROG) $(USRSBINPROG)

SRCS= 		$(PROG:%=%.c)

editmap :=	LDLIBS += -lldap
mail.local :=	LDLIBS += -lsocket -lnsl -lmail -lldap
mailq :=	LDLIBS += -lsecdb
mailstats :=	LDLIBS += -lldap
makemap :=	LDLIBS += -lldap
mconnect :=	LDLIBS += -lsocket -lnsl
praliases :=	LDLIBS += -lldap
smrsh :=	LDLIBS += -lldap
vacation :=	LDLIBS += -lldap
$(ROOTLIBSMTPSM)/mailq :=	FILEMODE = 4555

INCPATH=	-I../src -I../db -I../include

ENVDEF=		-DNOT_SENDMAIL
SUNENVDEF=	-DSUN_EXTENSIONS -DUSE_VENDOR_CF_PATH
DBMDEF=		-DNDBM -DNEWDB

CPPFLAGS =	$(INCPATH) $(ENVDEF) $(SUNENVDEF) $(DBMDEF) $(CPPFLAGS.sm)

# Nearly every support application provides sleep().  This isn't incompatible
# with libc, but can be confined to the applications themselves.
LDFLAGS +=	$(MAPFILE.NGB:%=-M%)

.KEEP_STATE:

all:		$(PROG) $(LIBSMTPSMPROG) $(LIBPROG) $(USRSBINPROG)

convtime.o:	../src/convtime.c
	$(COMPILE.c) ../src/convtime.c
	$(POST_PROCESS_O)

vacation:	vacation.o convtime.o rfc2047.o ../libsm/libsm.a
	$(LINK.c) vacation.o convtime.o rfc2047.o -o $@ $(LDLIBS) \
		../libsm/libsm.a
	$(POST_PROCESS)

mail.local:	mail.local.o ../libsmutil/libsmutil.a ../libsm/libsm.a
	$(LINK.c) mail.local.o -o $@ $(LDLIBS) ../libsmutil/libsmutil.a \
		../libsm/libsm.a
	$(POST_PROCESS)

smrsh:	smrsh.o ../libsm/libsm.a
	$(LINK.c) smrsh.o -o $@ $(LDLIBS) ../libsm/libsm.a
	$(POST_PROCESS)

makemap:	makemap.o ../libsmutil/libsmutil.a ../libsmdb/libsmdb.a \
			../db/libdb.a ../libsm/libsm.a
	$(LINK.c) makemap.o -o $@ $(LDLIBS) ../libsmdb/libsmdb.a \
		../libsmutil/libsmutil.a ../db/libdb.a ../libsm/libsm.a
	$(POST_PROCESS)

editmap:	editmap.o ../libsmutil/libsmutil.a ../libsmdb/libsmdb.a \
			../db/libdb.a ../libsm/libsm.a
	$(LINK.c) editmap.o -o $@ $(LDLIBS) ../libsmdb/libsmdb.a \
		../libsmutil/libsmutil.a ../db/libdb.a ../libsm/libsm.a
	$(POST_PROCESS)

praliases:	praliases.o ../libsmutil/libsmutil.a ../libsmdb/libsmdb.a \
			../libsm/libsm.a
	$(LINK.c) praliases.o -o $@ $(LDLIBS) ../libsmdb/libsmdb.a \
		../libsmutil/libsmutil.a ../db/libdb.a ../libsm/libsm.a
	$(POST_PROCESS)

mailstats:	mailstats.o ../libsmutil/libsmutil.a ../libsm/libsm.a
	$(LINK.c) mailstats.o -o $@ $(LDLIBS) ../libsmutil/libsmutil.a \
		../libsm/libsm.a
	$(POST_PROCESS)

install: all $(ROOTPROG) $(ROOTLIB)/mail.local $(ROOTLIB)/smrsh \
	$(ROOTLIBSMTPSM)/mailq $(ROOTUSRSBIN)/makemap \
	$(ROOTUSRSBIN)/etrn $(ROOTUSRSBIN)/editmap

clean:
	$(RM) $(OBJS) *.o

lint:		lint_PROG


include	../../Makefile.targ
