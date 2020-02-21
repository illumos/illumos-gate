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
# Copyright 2020 Joyent, Inc.
#

LIBRARY= kldap.a
VERS= .1

# XXX need to set the install path to plugin dir

# ldap plugin objects
LDAP_OBJS= \
	ldap_exp.o

OBJECTS= $(LDAP_OBJS)

# include library definitions
include $(SRC)/lib/krb5/Makefile.lib

LIBS=		$(DYNLIB)
SRCS=	$(LDAP_OBJS:%.o=../%.c)

include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

#override liblink
INS.liblink=	-$(RM) $@; $(SYMLINK) $(LIBLINKS)$(VERS) $@

CPPFLAGS +=	-DHAVE_CONFIG_H \
		-I$(SRC)/cmd/krb5/iprop \
		-I$(SRC)/lib/krb5 \
		-I$(SRC)/lib/krb5/kdb \
		-I$(SRC)/lib/krb5/plugins/kdb/ldap/libkdb_ldap \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include \
		-I$(SRC)/lib/gss_mechs/mech_krb5/krb5/os \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include/krb5 \
		-I$(SRC)/uts/common/gssapi/include/ \
		-I$(SRC)/uts/common/gssapi/mechs/krb5/include \
		-DKRB5_DEPRECATED=1 -DKRB5_PRIVATE=1 \
		-DUSE_KADM5_API_VERSION=2

CFLAGS +=	$(CCVERBOSE)
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-unused-function

DYNFLAGS +=	$(KERBRUNPATH)
# setting -L $(ROOT)/usr/lib/gss because libkdb_ldap needs mech_krb5
LDLIBS +=	-L $(ROOT)/usr/lib/gss -L $(ROOTLIBDIR) -lkdb_ldap

.KEEP_STATE:

all:	$(LIBS)

# include library targets
include $(SRC)/lib/krb5/Makefile.targ

FRC:
