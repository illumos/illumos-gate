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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libdhcpsvc/modules/files0/Makefile.com

LIBRARY = ds_SUNWfiles.a
VERS    = .0
LOCOBJS = dhcptab.o dhcp_network.o
OBJECTS = $(LOCOBJS) util.o general.o

# include library definitions
include $(SRC)/lib/libdhcpsvc/modules/Makefile.com

SRCS    = $(LOCOBJS:%.o=../%.c) $(UTILDIR)/util.c ../../files/general.c
LDLIBS += -lc -lnsl -linetutil -ldhcpsvc -lgen
CPPFLAGS += -D_FILE_OFFSET_BITS=64 -I$(UTILDIR)

.KEEP_STATE:

all:	$(LIBS)

# include library targets
include $(SRC)/lib/libdhcpsvc/modules/Makefile.targ

pics/general.o:	../../files/general.c
	$(COMPILE.c) -o $@ ../../files/general.c
	$(POST_PROCESS_O)
