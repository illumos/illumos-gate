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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Makefile for Kerberos client-install utility.
#

PROG=		ksetpw \
		kdyndns \
		ksmb

SHFILES=	kclient
SECFILES=	pam_krb5_first \
		pam_krb5_only \
		pam_krb5_optional
CLOBBERFILES=	$(SHFILES)

KRB5SBINSHFILES=$(SHFILES:%=$(KRB5SBIN)/%)

USRLIBSEC=	$(ROOT)/usr/lib/security
SEC=		$(SECFILES:%=$(USRLIBSEC)/%)
$(SEC):=	FILEMODE = $(LIBFILEMODE)

KS_OBJS=	ksetpw.o
KD_OBJS=	kdyndns.o
KSMB_OBJS=	ksmb.o

OBJS=		$(KS_OBJS) $(KD_OBJS) $(KSMB_OBJS)

SSRCS=	kclient.sh
SRCS=	$(OBJS:%.o=%.c)

include ../../../Makefile.cmd
include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

POFILE=	$(SSRCS:%.sh=%.po)

CPPFLAGS += -I$(SRC)/uts/common/gssapi/include \
	-I$(SRC)/lib/krb5 -I$(SRC)/lib/gss_mechs/mech_krb5/include \
	-I$(SRC)/uts/common/gssapi/include  \
	-I$(SRC)/uts/common/gssapi/mechs/krb5/include

LDFLAGS += $(KRUNPATH)

KSLDLIBS=	$(LDLIBS) $(KMECHLIB)
KDLDLIBS=	$(LDLIBS) -L$(ROOT)/usr/lib/smbsrv

DYNFLAGS +=	-R/usr/lib/smbsrv

.KEEP_STATE:

all: $(PROG) $(SHFILES) $(SEC)

install: all $(KRB5SBIN) $(KRB5SBINSHFILES) $(KRB5LIBSHFILES) $(KRB5LIBPROG)

kdyndns:	$(KD_OBJS)
	$(LINK.c) $(KD_OBJS) -o $@ $(DYNFLAGS) $(KDLDLIBS) -lsmbns
	$(POST_PROCESS)

ksmb:		$(KSMB_OBJS)
	$(LINK.c) $(KSMB_OBJS) -o $@ $(DYNFLAGS) $(KDLDLIBS) -lsmb
	$(POST_PROCESS)

ksetpw:		$(KS_OBJS)
	$(LINK.c) $(KS_OBJS) -o $@ $(KSLDLIBS)
	$(POST_PROCESS)

$(KRB5SBIN):
	$(INS.dir)

$(USRLIBSEC)/%: %
	$(INS.file)

clean:
	$(RM) $(PROG) $(SHFILES)

lint:	lint_SRCS

include ../../../Makefile.targ
