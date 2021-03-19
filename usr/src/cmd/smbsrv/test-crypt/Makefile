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
# Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2018-2021 Tintri by DDN, Inc. All rights reserved.
#


PROG=	test-encrypt test-decrypt

LIBFAKEKERN=../../../lib/libfakekernel/common
LIBFKSMBSRV=../../../lib/smbsrv/libfksmbsrv/common
SMBSRV_SRCDIR=../../../uts/common/fs/smbsrv
SMBSRV_CMNDIR=../../../common/smbsrv

include ../../Makefile.cmd
include ../../Makefile.ctf

ZGUIDANCE=

# Note: need our sys includes _before_ ENVCPPFLAGS, proto etc.
# The real cmn_err.h has conflicts w stdio printf (fix?)
CPPFLAGS.first += -I.
CPPFLAGS.first += -I$(LIBFAKEKERN)

INCS +=	-I../../../uts/common
INCS +=	-I../../../uts/common/smbsrv
INCS +=	-I../../../common/smbsrv

CSTD=		$(CSTD_GNU99)
C99LMODE=	-Xc99=%all

CFLAGS += $(CCVERBOSE)
CFLAGS64 += $(CCVERBOSE)

CERRWARN	+= -_gcc=-Wno-parentheses

CPPFLAGS += -D_REENTRANT
CPPFLAGS += -DTESTJIG
CPPFLAGS += -Dsyslog=smb_syslog
CPPFLAGS += -D_LARGEFILE64_SOURCE=1
CPPFLAGS += -D_FAKE_KERNEL

# Always debug here
CPPFLAGS += -DDEBUG
CPPFLAGS += $(INCS)

LDFLAGS += $(ZNOLAZYLOAD)
LDLIBS += -lfakekernel
LDLIBS += -lpkcs11

ROOTSMBDDIR = $(ROOTLIB)/smbsrv
ROOTSMBDFILE = $(PROG:%=$(ROOTSMBDDIR)/%)

OBJS=

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTSMBDFILE)

clean:
	-$(RM) *.o

lint:

TEOBJS= test_encrypt.o utils.o fksmb_encrypt_pkcs.o
test-encrypt := OBJS = $(TEOBJS)
test-encrypt : $(TEOBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)


TDOBJS= test_decrypt.o utils.o fksmb_encrypt_pkcs.o
test-decrypt := OBJS = $(TDOBJS)
test-decrypt : $(TDOBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

include ../../Makefile.targ

# LIBFKSMBSRV
%.o: $(LIBFKSMBSRV)/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) \
	  -I../../../uts/common/smbsrv \
	  -I../../../common/smbsrv -c $<
	$(POST_PROCESS_O)

$(ROOTSMBDDIR)/%: %
	$(INS.file)

.KEEP_STATE:
