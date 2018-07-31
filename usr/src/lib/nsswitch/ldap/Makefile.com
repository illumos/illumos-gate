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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

LIBRARY =	libnss_ldap.a
VERS =		.1

OBJECTS =	getauthattr.o	\
		getauuser.o	\
		getbootparams.o	\
		getether.o	\
		getexecattr.o	\
		getgrent.o	\
		gethostent.o	\
		gethostent6.o	\
		getkeyent.o	\
		getnetent.o	\
		getnetgrent.o	\
		getnetmasks.o	\
		getprofattr.o	\
		getprojent.o	\
		getprotoent.o	\
		getpwnam.o	\
		getprinter.o	\
		getrpcent.o	\
		getservent.o	\
		getspent.o	\
		getuserattr.o	\
		tsol_getrhent.o	\
		tsol_gettpent.o	\
		ldap_common.o	\
		ldap_utils.o

# include common nsswitch library definitions.
include		../../Makefile.com

CPPFLAGS +=	-I../../../libsldap/common
LDLIBS +=	-lsldap -lnsl -lldap
LINTFLAGS +=	-erroff=E_GLOBAL_COULD_BE_STATIC2
LINTFLAGS64 +=	-erroff=E_GLOBAL_COULD_BE_STATIC2
DYNLIB1 =	nss_ldap.so$(VERS)
