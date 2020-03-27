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

LIBRARY= libkdb_ldap.a
VERS= .1

LIBKLDAP_OBJS= \
	kdb_ldap.o \
	kdb_ldap_conn.o \
	kdb_xdr.o \
	ldap_create.o \
	ldap_err.o \
	ldap_fetch_mkey.o \
	ldap_handle.o \
	ldap_krbcontainer.o \
	ldap_misc.o \
	ldap_principal.o \
	ldap_principal2.o \
	ldap_pwd_policy.o \
	ldap_realm.o \
	ldap_service_rights.o \
	ldap_service_stash.o \
	ldap_services.o \
	ldap_tkt_policy.o \
	princ_xdr.o

OBJECTS= $(LIBKLDAP_OBJS)

# include library definitions
include $(SRC)/lib/krb5/Makefile.lib

SRCS= $(LIBKLDAP_OBJS:%.o=../%.c)

LIBS=		$(DYNLIB)

include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

POFILE = $(LIBRARY:%.a=%.po)
POFILES = generic.po

#override liblink
INS.liblink=	-$(RM) $@; $(SYMLINK) $(LIBLINKS)$(VERS) $@

CPPFLAGS +=	-DHAVE_CONFIG_H \
		-I$(SRC)/lib/krb5 \
		-I$(SRC)/lib/krb5/kdb \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include \
		-I$(SRC)/lib/gss_mechs/mech_krb5/krb5/os \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include/krb5 \
		-I$(SRC)/uts/common/gssapi/include/ \
		-I$(SRC)/uts/common/gssapi/mechs/krb5/include \
		-DUSE_KADM5_API_VERSION=2

CFLAGS +=	$(CCVERBOSE) -I..
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-unused-function

# not linted
SMATCH=off

DYNFLAGS +=	$(KRUNPATH) $(KERBRUNPATH) $(KMECHLIB)
LDLIBS +=	-L $(ROOTLIBDIR) -lkadm5srv -lc -lnsl -lldap

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
