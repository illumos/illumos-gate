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

LIBRARY=	passwdutil.a
VERS=		.1
OBJ=		__check_history.o \
		__set_authtoken_attr.o \
		__get_authtoken_attr.o \
		__user_to_authenticate.o \
		__verify_rpc_passwd.o \
		__failed_count.o \
		files_attr.o	\
		nis_attr.o	\
		npd_clnt.o	\
		nisplus_attr.o	\
		ldap_attr.o	\
		nss_attr.o	\
		switch_utils.o	\
		utils.o		\
		debug.o		\
		bsd-strsep.o

DERIVED_OBJ=	nispasswd_xdr.o

OBJECTS=	$(OBJ) $(DERIVED_OBJ)

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

#
# We depend upon a rpcgen file. Specify some additional macros
# to correctly build and get rid of the derived file
#
PROTOCOL_DIR=	../../../head/rpcsvc
DERIVED_FILES=	../nispasswd_xdr.c
CLOBBERFILES += $(DERIVED_FILES)

#
# Don't lint derived files
#
lint	:=	SRCS= $(OBJ:%.o=$(SRCDIR)/%.c)

.KEEP_STATE:

all:	$(LIBS)

../nispasswd_xdr.c: $(PROTOCOL_DIR)/nispasswd.x
	$(RPCGEN) -c -C -M $(PROTOCOL_DIR)/nispasswd.x > ../nispasswd_xdr.c

lint:	lintcheck

include ../../Makefile.targ
