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
# Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
# Copyright 2019, Joyent, Inc.
# Copyright 2024 RackTop Systems, Inc.
#

LIBRARY =	libfknsmb.a
VERS =		.1

OBJS_LOCAL = \
	fksmb_crypt_pkcs.o \
	fksmb_sign_pkcs.o \
	fake_ddi.o \
	fake_fio.o \
	fake_kmem.o \
	fake_ktli.o \
	fake_pkey.o \
	fake_policy.o \
	fake_sdt.o \
	fake_softc.o \
	fake_stream.o \
	fake_strsubr.o

# See also: $SRC/uts/common/Makefile.files
# NB: Intentionally ommitted, compared w/ the above:
#  smb_dev.o smb_pass.o	nsmb_*_kcf.o
#
OBJS_NSMB = \
	nsmb_kdf.o \
	smb_dev.o \
	smb_conn.o \
	smb_iod.o \
	smb_rq.o \
	smb_sign.o \
	smb_smb.o \
	smb_subrs.o \
	smb_time.o \
	smb_tran.o \
	smb_trantcp.o \
	smb_usr.o \
	smb2_rq.o \
	smb2_sign.o \
	smb2_smb.o \
	smb3_crypt.o \
	subr_mchain.o

OBJECTS = \
	$(OBJS_LOCAL) \
	$(OBJS_NSMB)

include ../../../Makefile.lib
include ../../Makefile.lib

# Force SOURCEDEBUG
CSOURCEDEBUGFLAGS	= -g
CCSOURCEDEBUGFLAGS	= -g
STRIP_STABS	= :

# Note: need our sys includes _before_ ENVCPPFLAGS, proto etc.
# Also, like Makefile.uts, reset CPPFLAGS
CPPFLAGS.first += -I../../../libfakekernel/common
CPPFLAGS.first += -I../common
CPPFLAGS= $(CPPFLAGS.first)

INCS += -I$(SRC)/uts/common/fs/smbclnt
INCS += -I$(SRC)/uts/common

CPPFLAGS += $(INCS) -D_REENTRANT -D_FAKE_KERNEL
CPPFLAGS += -D_FILE_OFFSET_BITS=64
# Always want DEBUG here
CPPFLAGS += -DDEBUG

CERRWARN += -_gcc=-Wno-switch

# needs work
SMOFF += all_func_returns,deref_check,signed

LDLIBS +=	$(MACH_LDLIBS)
LDLIBS +=	-lfakekernel -lpkcs11 -lnsl -lc

# libfknsmb isn't delivered, and is a special case, disable global data complaints
ZGUIDANCE= -Wl,-zguidance=noasserts

NSMB_DIR=$(SRC)/uts/common/fs/smbclnt/netsmb
SRCS=   $(OBJS_LOCAL:%.o=$(SRCDIR)/%.c) \
	$(OBJS_NSMB:%.o=$(NSMB_DIR)/%.c)

all:

pics/%.o:	$(NSMB_DIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

.KEEP_STATE:

include ../../Makefile.targ
include ../../../Makefile.targ
