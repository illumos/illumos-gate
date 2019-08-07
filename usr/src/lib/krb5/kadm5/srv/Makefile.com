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

LIBRARY= libkadm5srv.a
VERS= .1

SRV_OBJS = svr_policy.o \
	svr_principal.o \
	server_acl.o \
	server_kdb.o \
	server_misc.o \
	server_init.o \
	server_dict.o \
	svr_iters.o \
	svr_chpass_util.o \
	adb_xdr.o \
	xdr_alloc.o \
	logger.o \
	chgpwd.o

SHARED_OBJS =  \
        misc_free.o \
        kadm_rpc_xdr.o \
        chpass_util.o \
        alt_prof.o \
	kadm_host_srv_names.o \
        str_conv.o

OBJECTS= $(SHARED_OBJS) $(SRV_OBJS)

# include library definitions
include ../../../Makefile.lib

SRCS=		$(SRV_OBJS:%.o=../%.c) \
		$(SHARED_OBJS:%.o=../../%.c)

KRB5LIB= 	$(ROOT)/usr/lib/krb5
LIBS=		$(DYNLIB)


include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

POFILE = $(LIBRARY:%.a=%.po)
POFILES = generic.po

#override liblink
INS.liblink=	-$(RM) $@; $(SYMLINK) $(LIBLINKS)$(VERS) $@

CPPFLAGS += -I.. -I../.. -I../../.. \
	-I$(SRC)/lib/krb5/kdb \
	-I$(SRC)/cmd/krb5/iprop \
	-I$(SRC)/lib/gss_mechs/mech_krb5/include \
	-I$(SRC)/lib/gss_mechs/mech_krb5/include/krb5 \
	-I$(SRC)/uts/common/gssapi/ \
	-I$(SRC)/uts/common/gssapi/include/ \
	-I$(SRC)/uts/common/gssapi/mechs/krb5/include \
	-I$(SRC)/lib/gss_mechs/mech_krb5/krb5/os \
	-DHAVE_STDLIB_H -DUSE_SOLARIS_SHARED_LIBRARIES \
	-DHAVE_LIBSOCKET=1 -DHAVE_LIBNSL=1 -DSETRPCENT_TYPE=void \
	-DENDRPCENT_TYPE=void -DHAVE_SYS_ERRLIST=1 -DNEED_SYS_ERRLIST=1 \
	-DHAVE_SYSLOG_H=1 -DHAVE_OPENLOG=1 -DHAVE_SYSLOG=1 -DHAVE_CLOSELOG=1 \
	-DHAVE_STEP=1 -DHAVE_RE_COMP=1 -DHAVE_RE_EXEC=1 -DHAVE_REGCOMP=1 \
	-DHAVE_REGEXEC=1 -DHAVE_STRFTIME=1 -DHAVE_VSPRINTF=1 \
	-DUSE_KADM5_API_VERSION=2

CFLAGS +=	$(CCVERBOSE) -I..

CERRWARN +=	-_gcc=-Wno-unused-function
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-type-limits
CERRWARN +=	$(CNOWARN_UNINIT)

SMOFF += all_func_returns,indenting

.KEEP_STATE:

all:	$(LIBS)

lint:	lintcheck

# include library targets
include ../../../Makefile.targ

pics/%.o: ../../%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

FRC:

generic.po: FRC
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext ../*.[ch] ../../*.[ch]`
	$(SED) "/^domain/d" messages.po > $@
	$(RM) messages.po
