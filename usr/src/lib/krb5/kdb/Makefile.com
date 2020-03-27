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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

LIBRARY= libkdb.a
VERS= .1

# kdb
KDBOBJS= \
	keytab.o \
	encrypt_key.o \
	decrypt_key.o \
	kdb_convert.o \
	kdb_cpw.o \
	kdb_default.o \
	kdb_log.o \
	kdb5.o

DERIVED_OBJS= \
	iprop_xdr.o

# Definitions needed to rpcgen iprop-related files
ISRCHDR= ../iprop.h
ISRCXDR= ../iprop_xdr.c
KRB5IPROPDIR=	$(SRC)/cmd/krb5/iprop
CMD= grep -v "usr/src/cmd/krb5/iprop" > $@

# libkdb5 needs to link against some files from kadm5
KADM5DIR=       $(SRC)/lib/krb5/kadm5
KADM5OBJS= alt_prof.o str_conv.o
KADM5SRCS= $(KADM5DIR)/$(KADM5OBJS:%.o=%.c)

OBJECTS= $(KDBOBJS) $(KADM5OBJS) $(DERIVED_OBJS)

# include library definitions
include ../../Makefile.lib

SRCS=		$(KDBOBJS:%.o=../%.c)
SRCS+=		$(DERIVED_OBJS:%.o=../%.c)
SRCS+=		$(KADM5SRCS)

LIBS=		$(DYNLIB)

include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

POFILE = $(LIBRARY:%.a=%.po)
POFILES = generic.po

# override liblink
INS.liblink=	-$(RM) $@; $(SYMLINK) $(LIBLINKS)$(VERS) $@

CPPFLAGS +=	-DHAVE_CONFIG_H -DHAVE_BT_RSEQ \
		-I$(KRB5IPROPDIR) \
		-I$(SRC)/lib/krb5 \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include \
		-I$(SRC)/lib/gss_mechs/mech_krb5/krb5/os \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include/krb5 \
		-I$(SRC)/uts/common/gssapi/include/ \
		-I$(SRC)/uts/common/gssapi/mechs/krb5/include

CFLAGS +=	$(CCVERBOSE) -I..

CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-unused-function
CERRWARN +=	-_gcc=-Wno-type-limits
CERRWARN +=	$(CNOWARN_UNINIT)
CERRWARN +=	-_gcc=-Wno-parentheses

SMOFF += indenting,all_func_returns,deref_check,signed

DYNFLAGS +=	$(KRUNPATH) $(KMECHLIB)
LDLIBS +=	-lc -lnsl

.KEEP_STATE:

all:	$(LIBS)

# Rules to rpcgen-erate derived files from the iprop.x spec file
$(ISRCHDR):	$(KRB5IPROPDIR)/iprop.x
	$(RM)	$@
	$(RPCGEN) -h $(KRB5IPROPDIR)/iprop.x > $@

$(ISRCXDR):	$(ISRCHDR) $(KRB5IPROPDIR)/iprop.x
	$(RM) $@
	$(RPCGEN) -c $(KRB5IPROPDIR)/iprop.x | $(CMD)

CLEANFILES +=	$(ISRCHDR) $(ISRCXDR)

# Explicitly state the dependancy on iprop.h
$(LIBS): $(ISRCHDR)

# include library targets
include ../../Makefile.targ

FRC:

generic.po: FRC
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext ../*.[ch]`
	$(SED) "/^domain/d" messages.po > $@
	$(RM) messages.po
