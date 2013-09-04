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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

SRCS =		account.c anlwrk.c bnuconvert.c callers.c		\
		chremdir.c cntrl.c conn.c cpmv.c ct.c			\
		cu.c dial.c dio.c dkbreak.c				\
		dkdial.c dkerr.c dkminor.c dtnamer.c eio.c		\
		expfile.c fio.c gename.c getargs.c getopt.c getprm.c	\
		getpwinfo.c gio.c gnamef.c gnxseq.c grades.c		\
		gtcfile.c gwd.c imsg.c in.uucpd.c interface.c limits.c	\
		line.c logent.c mailst.c perfstat.c			\
		permission.c pk0.c pk1.c pkdefs.c security.c		\
		setmode.c shio.c statlog.c stoa.c strpbrk.c	\
		strsave.c sysfiles.c systat.c ulockf.c unknown.c	\
		utility.c uucheck.c uucico.c uucleanup.c uucp.c		\
		uucpdefs.c uucpname.c uudecode.c uuencode.c		\
		uuglist.c uuname.c uusched.c uustat.c uux.c		\
		uuxqt.c versys.c xio.c xqt.c

CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-char-subscripts
CERRWARN	+= -_gcc=-Wno-unused-variable
CERRWARN	+= -_gcc=-Wno-uninitialized
CERRWARN	+= -_gcc=-Wno-extra
CERRWARN	+= -_gcc=-Wno-implicit-function-declaration

TLILIB =	-lnsl -lsocket
PAMLIB =        -lpam

# use this if you don't have strpbrk/getopt in libc
# STRPBRK =	strpbrk.o
# GETOPT =	getopt.o

PROTOCOLOBJS =	dio.o eio.o gio.o xio.o fio.o

OTHEROBJS =	utility.o cpmv.o expfile.o gename.o getpwinfo.o \
		ulockf.o xqt.o logent.o gnamef.o systat.o	\
		sysfiles.o strsave.o $(GETOPT)

uucp \
uucp.cat :=	POBJS =	uucpdefs.o uucp.o gwd.o permission.o getargs.o	\
			getprm.o uucpname.o versys.o gtcfile.o grades.o	\
			$(STRPBRK) chremdir.o mailst.o $(OTHEROBJS)

uux \
uux.cat :=	POBJS =	uucpdefs.o uux.o mailst.o gwd.o permission.o	\
			getargs.o getprm.o uucpname.o versys.o gtcfile.o \
			grades.o chremdir.o $(STRPBRK) $(OTHEROBJS)

uuxqt \
uuxqt.cat :=	POBJS =	uucpdefs.o uuxqt.o mailst.o getprm.o uucpname.o \
			permission.o getargs.o gtcfile.o grades.o	\
			$(STRPBRK) shio.o chremdir.o account.o		\
			perfstat.o statlog.o security.o limits.o	\
			$(OTHEROBJS)

uucico \
uucico.cat :=	POBJS =	uucpdefs.o uucico.o conn.o callers.o cntrl.o	\
			pk0.o pk1.o anlwrk.o permission.o getargs.o	\
			gnxseq.o pkdefs.o imsg.o gtcfile.o grades.o	\
			mailst.o uucpname.o line.o chremdir.o		\
			interface.o statlog.o stoa.o			\
			perfstat.o account.o security.o limits.o	\
			$(STRPBRK) $(PROTOCOLOBJS) $(OTHEROBJS)		\
			versys.o setmode.o
uucico:=	PLIBS =	$(TLILIB) -lgen

uuname \
uuname.cat :=	POBJS =	uuname.o uucpname.o uucpdefs.o getpwinfo.o	\
			sysfiles.o strsave.o getargs.o

uustat \
uustat.cat :=	POBJS =	uustat.o gnamef.o expfile.o uucpdefs.o		\
			getpwinfo.o ulockf.o getargs.o utility.o	\
			uucpname.o versys.o strsave.o sysfiles.o	\
			cpmv.o mailst.o permission.o $(STRPBRK)	\
			$(GETOPT)

uusched \
uusched.cat :=	POBJS =	uusched.o gnamef.o expfile.o uucpdefs.o		\
			getpwinfo.o ulockf.o systat.o getargs.o		\
			utility.o limits.o permission.o uucpname.o	\
			$(GETOPT)

uucleanup \
uucleanup.cat := POBJS = uucleanup.o gnamef.o expfile.o uucpdefs.o	\
			getpwinfo.o uucpname.o ulockf.o getargs.o	\
			cpmv.o utility.o $(GETOPT)

uuglist \
uuglist.cat :=	POBJS =	grades.o cpmv.o getargs.o getpwinfo.o strsave.o	\
			uuglist.o uucpdefs.o expfile.o uucpname.o $(GETOPT)

bnuconvert \
bnuconvert.cat := POBJS = bnuconvert.o uucpdefs.o grades.o strsave.o	\
			getpwinfo.o getargs.o cpmv.o chremdir.o		\
			expfile.o gename.o gnamef.o gtcfile.o logent.o	\
			systat.o ulockf.o utility.o uucpname.o $(GETOPT)

remote.unknown \
remote.unknown.cat := POBJS =	unknown.o

cu \
cu.cat :=	POBJS =	cu.o callers.o getargs.o line.o uucpdefs.o	\
			ulockf.o conn.o interface.o strsave.o		\
			sysfiles.o stoa.o setmode.o
cu:=		PLIBS =	$(TLILIB) -lgen

ct \
ct.cat :=	POBJS =	ct.o callers.o getargs.o line.o uucpdefs.o	\
			ulockf.o conn.o interface.o sysfiles.o		\
			strsave.o stoa.o setmode.o
ct:=		PLIBS =	$(TLILIB) -lgen

uudecode \
uudecode.cat :=	POBJS =	uudecode.o common.o

uuencode \
uuencode.cat :=	POBJS =	uuencode.o

uucheck \
uucheck.cat :=	POBJS =	uucheck.o uucpname.o getargs.o $(GETOPT)

in.uucpd \
in.uucpd.cat :=	POBJS = in.uucpd.o
in.uucpd:=	PLIBS = $(TLILIB) $(PAMLIB)
