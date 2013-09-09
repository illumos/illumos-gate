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
# Copyright (c) 2013 RackTop Systems.
#
# cmd/oamuser/group/Makefile
#

include ../../Makefile.cmd

GROUPADD= 	groupadd
GROUPDEL= 	groupdel
GROUPMOD= 	groupmod

SBINPROG=	$(GROUPADD)   $(GROUPDEL)   $(GROUPMOD)

PROG=		$(SBINPROG)

ADD_OBJ=	groupadd.o    add_group.o   messages.o
DEL_OBJ=	groupdel.o    del_group.o   messages.o
MOD_OBJ=	groupmod.o    mod_group.o   messages.o

OBJECTS=	$(ADD_OBJ)    $(DEL_OBJ)    $(MOD_OBJ)
SRCS=		$(OBJECTS:.o=.c)

LIBDIR=		../lib
LIBUSRGRP=	$(LIBDIR)/lib.a
LOCAL=		../inc
HERE=		.
LINTFLAGS=	-u

INSSBINPROG=	$(SBINPROG:%=$(ROOTUSRSBIN)/%)

CPPFLAGS=	-I$(HERE) -I$(LOCAL) $(CPPFLAGS.master)
FILEMODE= 	0555

$(GROUPADD) :=	OBJS = $(ADD_OBJ)
$(GROUPADD) :=	LDLIBS += $(LIBUSRGRP) -lcmdutils

$(GROUPDEL) :=	OBJS = $(DEL_OBJ)
$(GROUPDEL) :=	LDLIBS += $(LIBUSRGRP)

$(GROUPMOD) :=	OBJS = $(MOD_OBJ)
$(GROUPMOD) :=	LDLIBS += $(LIBUSRGRP)

all: 		$(PROG)

$(PROG):	$$(OBJS) $(LIBUSRGRP)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(GROUPADD):	$(ADD_OBJ)
$(GROUPMOD):	$(MOD_OBJ)
$(GROUPDEL):	$(DEL_OBJ)

install:	all $(INSSBINPROG)

clean:
	$(RM) $(OBJECTS)

lint:	lint_SRCS

include ../../Makefile.targ
