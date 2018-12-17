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

LIBRARY= pkinit.a
VERS= .1

PKINIT_OBJS= \
	pkinit_accessor.o \
	pkinit_clnt.o \
	pkinit_crypto_openssl.o \
	pkinit_identity.o \
	pkinit_lib.o \
	pkinit_matching.o \
	pkinit_profile.o \
	pkinit_srv.o


OBJECTS= $(PKINIT_OBJS)

# include library definitions
include $(SRC)/lib/krb5/Makefile.lib

SRCS= $(PKINIT_OBJS:%.o=../%.c)

LIBS=		$(DYNLIB)

include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

POFILE = $(LIBRARY:%.a=%.po)
POFILES = generic.po

#override liblink
INS.liblink=	-$(RM) $@; $(SYMLINK) $(LIBLINKS)$(VERS) $@


CPPFLAGS += 	-I$(SRC)/lib/krb5 \
		-I$(SRC)/lib/krb5/kdb \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include \
		-I$(SRC)/lib/gss_mechs/mech_krb5/krb5/os \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include/krb5 \
		-I$(SRC)/uts/common/gssapi/include/ \
		-I$(SRC)/uts/common/gssapi/mechs/krb5/include \
		-I$(SRC)

CERRWARN	+= -_gcc=-Wno-uninitialized
CERRWARN	+= -_gcc=-Wno-unused-function

# not linted
SMATCH=off

CFLAGS +=	$(CCVERBOSE) -I..
DYNFLAGS +=	$(KRUNPATH) $(KMECHLIB) -znodelete
LDLIBS +=	-L $(ROOTLIBDIR) -lcrypto -lc

ROOTLIBDIR= $(ROOT)/usr/lib/krb5/plugins/preauth

$(ROOTLIBDIR):
	$(INS.dir)

.KEEP_STATE:

all:	$(LIBS)

lint:	lintcheck

# include library targets
include $(SRC)/lib/krb5/Makefile.targ

FRC:

generic.po: FRC
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext ../*.[ch]`
	$(SED) "/^domain/d" messages.po > $@
	$(RM) messages.po
