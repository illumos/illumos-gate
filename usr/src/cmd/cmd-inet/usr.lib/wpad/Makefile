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
# Copyright (c) 2018, Joyent, Inc.

PROG =		wpad
MANIFEST =	wpa.xml
OBJS =		wpa_supplicant.o wpa.o wpa_enc.o eloop.o \
		driver_wifi.o l2_packet.o
SRCS =		$(OBJS:%.o=%.c)

include	../../../Makefile.cmd

ROOTMANIFESTDIR = $(ROOTSVCNETWORK)

# The wpa_enc.c file is not ported to the OpenSSL 3.x API yet and so we need to
# make sure the deprecated 1.x API is fully available for it.  Once the
# wpa_enc.c file is adapted for OpenSSL 3.x this should be updated or removed.
# See also https://www.illumos.org/issues/16917
CPPFLAGS +=	-DOPENSSL_API_COMPAT=10101

LDLIBS +=	-ldladm -ldlpi
NATIVE_LIBS +=	libcrypto.so
all install := LDLIBS += -lcrypto

SMOFF += all_func_returns

.KEEP_STATE:

all:		$(PROG)

$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

include ../Makefile.lib

install:	all $(ROOTLIBINETPROG) $(ROOTMANIFEST)

check:		$(CHKMANIFEST)

clean:
		$(RM) $(OBJS)

include ../../../Makefile.targ
