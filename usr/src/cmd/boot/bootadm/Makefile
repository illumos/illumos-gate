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
# Copyright 2011 Nexenta Systems, Inc. All rights reserved.
# Copyright 2016 Toomas Soome <tsoome@me.com>
#

PROG= bootadm

SBINLINKS= $(PROG)

OBJS= bootadm.o bootadm_upgrade.o bootadm_hyper.o bootadm_digest.o
SRCS = $(OBJS:.o=.c)

include ../Makefile.com


.KEEP_STATE:

LDLIBS_i386= -lfdisk
LDLIBS +=	-lpkcs11 -lcryptoutil -lnvpair -lgen -ladm -lefi -lscf -lz -lbe -lzfs $(LDLIBS_$(MACH))

# Writing into string literals is incorrect.  We need to match gcc's
# behavior, which causes us to take SIGSEGV on such a write.
CFLAGS +=	$(XSTRCONST)
CPPFLAGS +=	-D_FILE_OFFSET_BITS=64
CPPFLAGS +=	-I../../../uts/common -I../../../common

C99MODE=	$(C99_ENABLE)

LINTFLAGS += -erroff=E_INCONS_ARG_DECL2
LINTFLAGS += -erroff=E_INCONS_VAL_TYPE_DECL2
LINTFLAGS += -erroff=E_NAME_DEF_NOT_USED2

all: $(PROG)

$(PROG): $(OBJS) bootadm.h
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTSBINPROG) .WAIT $(ROOTUSRSBINLINKS)

clean:
	-$(RM) $(OBJS)

_msg:

lint:	lint_SRCS

include ../Makefile.targ
