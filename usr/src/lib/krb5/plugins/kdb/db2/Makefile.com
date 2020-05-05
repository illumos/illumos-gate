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

LIBRARY= db2.a
VERS= .1

# XXX need to set the install path to plugin dir

# db2 plugin objects
DB2_OBJS= \
	adb_openclose.o \
	adb_policy.o \
	db2_exp.o \
	kdb_db2.o \
	kdb_xdr.o \
	pol_xdr.o

OBJECTS= $(DB2_OBJS)

# include library definitions
include $(SRC)/lib/krb5/Makefile.lib

LIBS=		$(DYNLIB)
SRCS=	$(DB2_OBJS:%.o=../%.c)

include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

POFILE = $(LIBRARY:%.a=%.po)
POFILES = generic.po

#override liblink
INS.liblink=	-$(RM) $@; $(SYMLINK) $(LIBLINKS)$(VERS) $@

CPPFLAGS +=	-DHAVE_CONFIG_H -DHAVE_BT_RSEQ \
		-I$(SRC)/cmd/krb5/iprop \
		-I$(SRC)/lib/krb5 \
		-I$(SRC)/lib/krb5/kdb \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include \
		-I$(SRC)/lib/gss_mechs/mech_krb5/krb5/os \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include/krb5 \
		-I$(SRC)/uts/common/gssapi/include/ \
		-I$(SRC)/uts/common/gssapi/mechs/krb5/include

CFLAGS +=	$(CCVERBOSE)
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-unused-function
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	$(CNOWARN_UNINIT)

# not linted
SMATCH=off

DYNFLAGS +=	$(KRUNPATH) $(KERBRUNPATH) $(KMECHLIB)
LDLIBS +=	-L $(ROOTLIBDIR) -ldb2 -lkdb -lkadm5srv -lc -lnsl

.KEEP_STATE:

all:	$(LIBS)


# include library targets
include $(SRC)/lib/krb5/Makefile.targ

FRC:

generic.po: FRC
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext ../*.[ch]`
	$(SED) "/^domain/d" messages.po > $@
	$(RM) messages.po
