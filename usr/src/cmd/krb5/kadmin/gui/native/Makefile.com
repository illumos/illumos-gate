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

LIBRARY=	libkadmin.a
VERS=		.1

CLASSES=	Kadmin
OBJECTS=	$(CLASSES:%=%.o)

include $(SRC)/lib/Makefile.lib
#
# Need this makefile to find the KRUNPATH, KERBRUNPATH and KMECHLIB definitions
#
include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

ROOTLIBDIR=	$(ROOT)/usr/lib/krb5
LIBS =		$(DYNLIB)

CPPFLAGS += -I../ -I$(SRC)/lib/krb5 \
	-I$(SRC)/lib/krb5/kadm5 \
	-I$(SRC)/lib/gss_mechs/mech_krb5/include \
	-I$(SRC)/lib/gss_mechs/mech_krb5/krb5/error_tables \
	-I$(SRC)/uts/common/gssapi/mechs/krb5/include \
	-I$(JAVA_ROOT)/include -I$(JAVA_ROOT)/include/solaris

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-unused-function

LDLIBS += $(KMECHLIB) -L$(ROOT)/$(KERBLIBDIR) -lkadm5clnt -lsocket -lc
DYNFLAGS += $(KRUNPATH) $(KERBRUNPATH)

#
# This library is not directly linked against by any C applications
# (only by Java code), so we do not build a lint library.
#

.KEEP_STATE:

all:	$(LIBS)

LINTFLAGS	= -mxus

lint: lintcheck

include $(SRC)/lib/Makefile.targ

