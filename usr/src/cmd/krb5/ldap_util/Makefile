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

PROG= kdb5_ldap_util

OBJS	= \
	kdb5_ldap_list.o \
	kdb5_ldap_policy.o \
	kdb5_ldap_realm.o \
	kdb5_ldap_services.o \
	kdb5_ldap_util.o \
	getdate.o

DEFS =  -DHAVE_LIBSOCKET=1 -DHAVE_LIBNSL=1 -DHAVE_PWD_H=1 -DHAVE_COMPILE=1 -DHAVE_STEP=1

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

TEXT_DOMAIN = SUNW_OST_OSCMD
POFILE = kdb5_ldap_util.po
POFILES = generic.po

DEFS = -DHAVE_PWD_H -DUSE_KADM5_API_VERSION=2

CPPFLAGS += \
		-I$(SRC)/lib/gss_mechs/mech_krb5 \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include/krb5 \
		-I$(SRC)/lib/krb5 \
		-I$(SRC)/lib/krb5/kdb \
		-I$(SRC)/lib/krb5/plugins/kdb/ldap/libkdb_ldap \
		-I$(SRC)/cmd/krb5/kadmin/cli \
		-I$(SRC)/uts/common/gssapi/mechs/krb5/include \
		-I$(SRC)/uts/common/gssapi/mechs/krb5/include/krb5 \
		-I../kwarn \
		$(DEFS)

CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-unused-function
CERRWARN +=	-_gcc=-Wno-implicit-function-declaration

# because of labels from yacc
getdate.o := CERRWARN += -_gcc=-Wno-unused-label

# not linted
SMATCH=off

LDFLAGS += $(KRUNPATH) $(KERBRUNPATH)
LDLIBS += -L $(ROOT_KLIBDIR) -L $(KRB5LIB) -lkadm5srv -lkdb -lkdb_ldap \
	-lmech_krb5

.KEEP_STATE:

all: $(PROG)

$(PROG):       $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: $(KRB5SBINPROG)

clean:
	$(RM) $(OBJS)

include $(SRC)/cmd/Makefile.targ

%.o:	$(SRC)/cmd/krb5/kadmin/cli/%.y
	$(YACC.y) $<
	$(COMPILE.c) -o $@ y.tab.c $(CTFCONVERT_HOOK)
	$(POST_PROCESS_O)
	$(RM) y.tab.c

$(POFILE): $(DERIVED_FILES) .WAIT $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

generic.po:
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `($(GREP) -l gettext *.[ch] || echo /dev/null)`
	$(SED) "/^domain/d" messages.po > $@
	$(RM) messages.po
