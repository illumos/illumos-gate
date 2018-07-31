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

LIBRARY =	libnss_files.a
VERS =		.1

OBJECTS =	bootparams_getbyname.o	\
		ether_addr.o		\
		files_common.o		\
		getgrent.o		\
		gethostent.o		\
		gethostent6.o		\
		getnetent.o		\
		getprojent.o		\
		getprotoent.o		\
		getpwnam.o		\
		getrpcent.o		\
		getprinter.o		\
		getservent.o		\
		getspent.o		\
		getauthattr.o		\
		getprofattr.o		\
		getexecattr.o		\
		getuserattr.o		\
		getauuser.o		\
		netmasks.o		\
		tsol_getrhent.o		\
		tsol_gettpent.o

# include common nsswitch library definitions.
include		../../Makefile.com

# install this library in the root filesystem
include ../../../Makefile.rootfs

CPPFLAGS +=	-I../../../common/inc
LINTFLAGS +=	-erroff=E_GLOBAL_COULD_BE_STATIC2
LINTFLAGS64 +=	-erroff=E_GLOBAL_COULD_BE_STATIC2

LDLIBS +=	-lnsl
DYNLIB1 =	nss_files.so$(VERS)

all: $(DYNLIB1)
