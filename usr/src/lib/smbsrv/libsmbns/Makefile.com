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
# Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
# 

LIBRARY= libsmbns.a
VERS= .1

OBJS_SHARED =			\
	smb_netbios_util.o	\

OBJS_COMMON=			\
	smbns_ads.o		\
	smbns_browser.o		\
	smbns_dyndns.o		\
	smbns_krb.o		\
	smbns_ksetpwd.o		\
	smbns_netbios.o		\
	smbns_netbios_cache.o	\
	smbns_netbios_datagram.o\
	smbns_netbios_name.o	\
	smbns_netlogon.o

OBJECTS=	$(OBJS_COMMON) $(OBJS_SHARED)

include ../../../Makefile.lib
include ../../Makefile.lib

SRCS=   $(OBJS_COMMON:%.o=$(SRCDIR)/%.c)	\
	$(OBJS_SHARED:%.o=$(SRC)/common/smbsrv/%.c)

LDLIBS +=	$(MACH_LDLIBS)
LDLIBS +=	-lsmb -lads -lgss -lcmdutils -lldap \
		-lsocket -lnsl -lc
CPPFLAGS +=	-D_REENTRANT
CPPFLAGS +=	-Dsyslog=smb_syslog
CERRWARN +=	-_gcc=-Wno-unused-function
CERRWARN +=	-_gcc=-Wno-uninitialized

# DYNLIB libraries do not have lint libs and are not linted
$(DYNLIB) :=	LDLIBS += -lkrb5

include ../../Makefile.targ
include ../../../Makefile.targ
