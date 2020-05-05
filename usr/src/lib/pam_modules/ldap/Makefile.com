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
# usr/src/lib/pam_modules/ldap/Makefile.com
#

LIBRARY=	pam_ldap.a
VERS=		 .1

OBJECTS=	ldap_authenticate.o \
		ldap_setcred.o \
		ldap_acct_mgmt.o \
		ldap_close_session.o \
		ldap_open_session.o \
		ldap_chauthtok.o \
		ldap_utils.o

include		../../Makefile.pam_modules

LDLIBS +=	-lpam -lsldap -lc
CPPFLAGS +=	-I$(SRC)/lib/libsldap/common
CERRWARN +=	-_gcc=-Wno-parentheses

all:	$(LIBS)


include $(SRC)/lib/Makefile.targ
