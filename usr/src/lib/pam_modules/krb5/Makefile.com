#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# usr/src/lib/pam_modules/krb5/Makefile.com
#
# ident	"%Z%%M%	%I%	%E% SMI"

LIBRARY=	pam_krb5.a
VERS=		.1

include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

PRIV_OBJ=	krb5_authenticate.o \
		krb5_setcred.o \
		krb5_acct_mgmt.o \
		krb5_password.o \
		krb5_session.o \
		utils.o

DERIVED_OBJ=	kwarnd_clnt_stubs.o \
		kwarnd_clnt.o \
		kwarnd_handle.o \
		kwarnd_xdr.o

OBJECTS=	$(PRIV_OBJ) $(DERIVED_OBJ)

JOBJ=		kwarnd.x \
		kwarnd.h \
		kwarnd_clnt_stubs.c \
		kwarnd_handle.c \
		kwarnd_xdr.c \
		kwarnd_clnt.c

include 	../../Makefile.pam_modules

CPPFLAGS +=	-I../../../gss_mechs/mech_krb5/include \
		-I$(SRC)/uts/common/gssapi/include/ \
		-I$(SRC)/uts/common/gssapi/mechs/krb5/include \
		-I$(SRC)/lib/gss_mechs/mech_krb5 \
		-I$(SRC)/lib/krb5 \
		-I.

# module needs to be unloadable because the key destructor might be
# called after dlclose()
DYNFLAGS +=	$(ZNODELETE)

CLOBBERFILES += $(LINTLIB) $(LINTOUT) $(JOBJ) $(POFILE)

#
# Don't lint derived files
#
lint    :=      SRCS= $(PRIV_OBJ:%.o=$(SRCDIR)/%.c)

all:	$(LIBS)

lint:	lintcheck

include	$(SRC)/lib/Makefile.targ

kwarnd.h:	$(SRC)/cmd/krb5/kwarn/kwarnd.x
	$(RM) $@
	$(RPCGEN) -M -h $(SRC)/cmd/krb5/kwarn/kwarnd.x | \
	$(SED) -e 's!$(SRC)/cmd/krb5/kwarn/kwarnd.h!kwarnd.h!' > $@

kwarnd_xdr.c:	kwarnd.h $(SRC)/cmd/krb5/kwarn/kwarnd.x
	$(RM) $@
	$(RPCGEN) -M -c $(SRC)/cmd/krb5/kwarn/kwarnd.x | \
	$(SED) -e 's!$(SRC)/cmd/krb5/kwarn/kwarnd.h!kwarnd.h!' > $@

kwarnd_clnt.c:   kwarnd.h $(SRC)/cmd/krb5/kwarn/kwarnd.x
	$(RM) $@
	$(RPCGEN) -M -l $(SRC)/cmd/krb5/kwarn/kwarnd.x | \
	$(SED) -e 's!$(SRC)/cmd/krb5/kwarn/kwarnd.h!kwarnd.h!' > $@

kwarnd_clnt_stubs.c: kwarnd.h $(SRC)/cmd/krb5/kwarn/kwarnd_clnt_stubs.c
	$(RM) $@
	$(CP) $(SRC)/cmd/krb5/kwarn/kwarnd_clnt_stubs.c $@

kwarnd_handle.c: $(SRC)/cmd/krb5/kwarn/kwarnd_handle.c
	$(RM) $@
	$(CP) $(SRC)/cmd/krb5/kwarn/kwarnd_handle.c $@
