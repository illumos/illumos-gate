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
# Copyright (c) 2018, Joyent, Inc.

LIBRARY= libss.a
VERS= .1

SSOBJS= \
	data.o \
	error.o \
	execute_cmd.o \
	help.o \
	invocation.o \
	list_rqs.o \
	listen.o \
	pager.o \
	parse.o \
	prompt.o \
	request_tbl.o \
	requests.o \
	std_rqs.o

OBJECTS= $(SSOBJS)

# include library definitions
include ../../Makefile.lib

SRCS=	$(SSOBJS:%.o=../%.c)

LIBS=		$(DYNLIB)

include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

#override liblink
INS.liblink=	-$(RM) $@; $(SYMLINK) $(LIBLINKS)$(VERS) $@

CPPFLAGS +=     -DHAVE_LIBSOCKET=1 -DHAVE_LIBNSL=1 -DHAS_STRDUP=1 \
		-DUSE_DIRENT_H=1 -DWAIT_USES_INT=1 -DPOSIX_SIGNALS=1 \
		-D_REENTRANT -DUSE_SIGPROCMASK=1 -DRETSIGTYPE=void \
		-DHAVE_STDARG_H=1 -DHAVE_STDLIB_H=1 -DHAVE_COMPILE=1 \
		-DHAVE_UNISTD_H=1 -DHAVE_UMASK=1 -DHAVE_SRAND48=1 \
		-DHAVESRAND=1 -DHAVESRANDOM=1 -DHAVE_RE_COMP=1 \
		-DHAVE_RE_EXEC=1 -DHAVE_REGCOMP=1 -DHAVE_REGEXEC=1 \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include \
		-I$(SRC)/lib/krb5

CFLAGS +=	$(CCVERBOSE) -I..
CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	-_gcc=-Wno-unused-variable

SMOFF += all_func_returns

DYNFLAGS +=	$(KRUNPATH) $(KMECHLIB) $(ZIGNORE)

LDLIBS +=	-lc -ltecla

$(PICS) :=      CFLAGS += $(XFFLAG)

.KEEP_STATE:

all:	$(LIBS)


# include library targets
include ../../Makefile.targ
