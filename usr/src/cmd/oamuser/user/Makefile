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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/oamuser/user/Makefile
#

include ../../Makefile.cmd

GREP=		grep

USERADD= 	useradd
USERDEL= 	userdel
USERMOD= 	usermod
PROFILE=	.profile
STDPROFILE=	stdprofile
ROLEADD=	roleadd
ROLEDEL=	roledel
ROLEMOD=	rolemod

SBINPROG=	$(USERADD)   $(USERDEL)   $(USERMOD)
SKELFILE=	$(PROFILE)
#
#	Removing sysadm: deleted $(SYSADMPROG) from this target.
#
PROG=		$(SBINPROG)
PRODUCT=	$(PROG) $(PROFILE)

ADD_OBJ=	useradd.o     uid.o        homedir.o \
		groups.o      call_pass.o      userdefs.o   messages.o \
		val_lgrp.o    funcs.o	       val_lprj.o   proj.o

DEL_OBJ=	userdel.o     call_pass.o      rmfiles.o    isbusy.o \
		groups.o      messages.o       funcs.o      proj.o

MOD_OBJ=	usermod.o     uid.o            movedir.o    groups.o \
		rmfiles.o     call_pass.o      isbusy.o     homedir.o \
		userdefs.o    messages.o       val_lgrp.o   funcs.o \
		val_lprj.o    proj.o

OBJECTS=	$(ADD_OBJ)     $(DEL_OBJ)    $(MOD_OBJ)

SRCS=		$(OBJECTS:.o=.c)

CLOBBERFILES=	$(PROFILE)
LIBDIR=		../lib
LIBUSRGRP=	$(LIBDIR)/lib.a
LIBADM=		-ladm
LOCAL=		../inc
HERE=		.
LINTFLAGS=	-u

ROOTSKEL=	$(ROOTETC)/skel
INSSBINPROG=	$(SBINPROG:%=$(ROOTUSRSBIN)/%)
INSSKELFILE=	$(SKELFILE:%=$(ROOTSKEL)/%)

CPPFLAGS=	-I$(HERE) -I$(LOCAL) $(CPPFLAGS.master)
OWNER= 		root
GROUP= 		sys

$(INSSBINPROG)  := FILEMODE = 0555
$(INSSYSADMPROG):= FILEMODE = 0500
$(INSSKELFILE)  := FILEMODE = 0644
$(INSSKELFILE)  := GROUP = other
$(ROOTSKEL)	:= OWNER = root
$(ROOTSKEL)	:= GROUP = sys

$(USERADD) :=	OBJS = $(ADD_OBJ)
$(USERADD) :=	LIBS = $(LIBUSRGRP)

$(USERDEL) :=	OBJS = $(DEL_OBJ)
$(USERDEL) :=	LIBS = $(LIBUSRGRP)

$(USERMOD) :=	OBJS = $(MOD_OBJ)
$(USERMOD) :=	LIBS = $(LIBUSRGRP)

LDLIBS +=	-lsecdb -lproject -ltsol

.PARALLEL: $(OBJECTS)

all: 		$(PRODUCT)

$(PROFILE):    $(STDPROFILE)
	$(GREP) -v "^#ident" $(STDPROFILE) > $(PROFILE)

$(PROG):	$$(OBJS) $$(LIBS)
	$(LINK.c) $(OBJS) -o $@ $(LIBS) $(LDLIBS)
	$(POST_PROCESS)

$(USERADD):	$(ADD_OBJ)
$(USERMOD):	$(MOD_OBJ)
$(USERDEL):	$(DEL_OBJ)

install:	all .WAIT $(ROOTSKEL) $(INSSBINPROG) $(INSSKELFILE)
		$(RM) $(ROOTUSRSBIN)/$(ROLEADD)
		$(LN) $(ROOTUSRSBIN)/$(USERADD) $(ROOTUSRSBIN)/$(ROLEADD)
		$(RM) $(ROOTUSRSBIN)/$(ROLEDEL)
		$(LN) $(ROOTUSRSBIN)/$(USERDEL) $(ROOTUSRSBIN)/$(ROLEDEL)
		$(RM) $(ROOTUSRSBIN)/$(ROLEMOD)
		$(LN) $(ROOTUSRSBIN)/$(USERMOD) $(ROOTUSRSBIN)/$(ROLEMOD)

$(ROOTSKEL):
	$(INS.dir)

$(ROOTSKEL)/%:	%
	$(INS.file)

clean:
	$(RM) $(OBJECTS)

lint:	lint_SRCS

include ../../Makefile.targ
