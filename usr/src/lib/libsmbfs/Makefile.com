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

#
# lib/libsmbfs/Makefile.com
#

LIBRARY=	libsmbfs.a
VERS=		.1

# leaving out: kiconv.o

OBJECTS=\
	acl_api.o \
	acl_conv.o \
	acl_print.o \
	charsets.o \
	cfopt.o \
	connect.o \
	crypt.o \
	ctx.o \
	derparse.o \
	file.o \
	findvc.o \
	getaddr.o \
	iod_cl.o \
	iod_wk.o \
	keychain.o \
	krb5ssp.o \
	mbuf.o \
	nb.o \
	nb_name.o \
	nb_net.o \
	nb_ssn.o \
	nbns_rq.o \
	negprot.o \
	netshareenum.o \
	newvc.o \
	nls.o \
	ntlm.o \
	ntlmssp.o \
	print.o \
	rap.o \
	rcfile.o \
	rq.o \
	signing.o \
	spnego.o \
	spnegoparse.o \
	ssnsetup.o \
	ssp.o \
	subr.o \
	ui-sun.o \
	utf_str.o

include $(SRC)/lib/Makefile.lib

LIBS =		$(DYNLIB) $(LINTLIB)

SRCDIR=		../smb

SRCS=		$(OBJECTS:%.o=../smb/%.c)

$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)

C99MODE=	$(C99_ENABLE)

LDLIBS += -lsocket -lnsl -lc -lmd -lpkcs11 -lkrb5 -lsec -lidmap

# normal warnings...
CFLAGS	+=	$(CCVERBOSE) 

CPPFLAGS += -D__EXTENSIONS__ -D_REENTRANT -DMIA \
	-I$(SRCDIR) -I.. -I$(SRC)/uts/common

# Debugging
${NOT_RELEASE_BUILD} CPPFLAGS += -DDEBUG

# uncomment these for dbx debugging
#COPTFLAG = -g
#CTF_FLAGS =
#CTFCONVERT_O=
#CTFMERGE_LIB=

# disable some of the less important lint
LINTCHECKFLAGS	+= -erroff=E_FUNC_RET_ALWAYS_IGNOR2
LINTCHECKFLAGS	+= -erroff=E_FUNC_RET_MAYBE_IGNORED2
LINTCHECKFLAGS	+= -DDEBUG

all:	$(LIBS)

lint:	lintcheck

include ../../Makefile.targ

.KEEP_STATE:
