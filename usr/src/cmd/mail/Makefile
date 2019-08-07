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
# Copyright (c) 2018, Joyent, Inc.
#

BINPROG=	mail

PROG= 	       $(BINPROG)

GREP=		grep

include ../Makefile.cmd

CLOBBERFILES=	$(PROG)
CLEANFILES=	$(MAILOBJS)

MAILOBJS= 	add_recip.o cat.o ckdlivopts.o \
		cksaved.o clr_hinfo.o copyback.o copylet.o \
		copymt.o createmf.o del_recipl.o Dout.o  delete.o \
		done.o doopen.o dumpaff.o dumprcv.o \
		errmsg.o gendeliv.o getarg.o getcomment.o \
		gethead.o goback.o init.o \
		isheader.o isit.o islocal.o istext.o legal.o \
		lock.o  main.o mkdead.o mta_ercode.o \
		new_recipl.o parse.o pckaffspot.o pckrcvspot.o \
		pickFrom.o pipletr.o poplist.o printhdr.o printmail.o \
		pushlist.o savehdrs.o sel_disp.o  sendlist.o \
		sendmail.o  setsig.o \
		stamp.o Tout.o

MAILSRC=	 $(MAILOBJS:%.o=%.c)

CPROG=		mail
CPROGSRC= 	$(CPROG:%=_%.c)

# ROOT directories
ROOTMAILD=	$(ROOTLIB)/mail
ROOTINC=	$(ROOT)/usr/include

# installed modules
ROOTBINPROG=	$(BINPROG:%=$(ROOTBIN)/%)

ROOTSYMLINKS=	$(ROOTBIN)/rmail


EDITPATH= \
	sed -e 's!REAL_PATH!/usr/bin!g' \
	    -e 's!USR_SHARE_LIB!/usr/share/lib!g' \
	    -e 's!VAR_MAIL!/var/mail!g' < $? > $@

CPPFLAGS =	-DSVR4 -I. $(CPPFLAGS.master)
CERRWARN +=	-_gcc=-Wno-implicit-function-declaration
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	$(CNOWARN_UNINIT)
CERRWARN +=	-_gcc=-Wno-clobbered
CERRWARN +=	-_gcc=-Wno-extra

# missing type declarations for old-style functions
SMATCH =	off

LDLIBS +=	-lmail -lsocket

# mail defines its own delete() - reduce symbols to locals to remove name clash.
LDFLAGS +=	$(MAPFILE.NGB:%=-M%)

# conditional assignments
#
all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber
lint:=		TARGET= lint

# file modes, owners and groups for the install target
#


$(ROOTBIN)/mail :=	FILEMODE =	02511


# install rules
$(ROOTINC)/% : %
	$(INS.file)

.KEEP_STATE:

.PARALLEL: $(MAILOBJS) $(OBJS)

all:		$(PROG)

mail: 		$(MAILOBJS)
	$(LINK.c) -o $@ $(MAILOBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all .WAIT $(ROOTBINPROG) $(ROOTSYMLINKS)

# ROOTSYMLINKS
#
$(ROOTBIN)/rmail:
	$(RM) $@; $(SYMLINK) mail $@

lint:
	$(LINT.c) $(MAILSRC)

clean:
	$(RM) $(OBJS) $(MAILOBJS)

clobber:
	$(RM) $(OBJS) $(MAILOBJS) mail
