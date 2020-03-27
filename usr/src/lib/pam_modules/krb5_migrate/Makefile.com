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
# usr/src/lib/pam_modules/krb5_migrate/Makefile.com
#

LIBRARY=	pam_krb5_migrate.a
VERS=		.1
OBJECTS=	krb5_migrate_authenticate.o

include		../../Makefile.pam_modules
include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

CPPFLAGS +=	-I../../../gss_mechs/mech_krb5/include \
		-I$(SRC)/uts/common/gssapi/include/ \
		-I$(SRC)/uts/common/gssapi/mechs/krb5/include \
		-I$(SRC)/lib/gss_mechs/mech_krb5 \
		-I$(SRC)/lib/krb5

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-unused-function

LDLIBS +=	-lpam -lc

all:	$(LIBS)


include		../../../Makefile.targ
