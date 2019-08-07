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

LIBRARY=	passwdutil.a
VERS=		.1
OBJ=		__check_history.o \
		__set_authtoken_attr.o \
		__get_authtoken_attr.o \
		__user_to_authenticate.o \
		__failed_count.o \
		files_attr.o	\
		nis_attr.o	\
		ldap_attr.o	\
		nss_attr.o	\
		switch_utils.o	\
		utils.o		\
		debug.o

OBJECTS=	$(OBJ)

include	../../Makefile.lib

#
# Since our name doesn't start with "lib", Makefile.lib incorrectly
# calculates LIBNAME. Therefore, we set it here.
#
LIBNAME=	passwdutil

LIBS=		$(DYNLIB) $(LINTLIB)
$(LINTLIB) :=	SRCS= $(SRCDIR)/$(LINTSRC)
LDLIBS		+= -lsldap -lnsl -lc

CPPFLAGS	+= -DENABLE_SUNOS_AGING -D_REENTRANT \
		   -I$(SRC)/lib/libsldap/common -I$(SRC)/lib/libnsl/include
CFLAGS		+= $(CCVERBOSE)

CERRWARN	+= -_gcc=-Wno-switch
CERRWARN	+= $(CNOWARN_UNINIT)
CERRWARN	+= -_gcc=-Wno-unused-label

# not linted
SMATCH=off

lint	:=	SRCS= $(OBJ:%.o=$(SRCDIR)/%.c)

.KEEP_STATE:

all:	$(LIBS)

lint:	lintcheck

include ../../Makefile.targ
