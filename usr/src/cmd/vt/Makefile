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
# Copyright 2015 RackTop Systems.
# Copyright 2020 Joyent, Inc.
#

PROG= vtdaemon vtinfo vtxlock

VTDAEMON_SRC= vtdaemon.c
VTDAEMON_OBJ= $(VTDAEMON_SRC:%.c=%.o)
vtdaemon := OBJS = $(VTDAEMON_OBJ)

VTINFO_SRC= vtinfo.c
VTINFO_OBJ= $(VTINFO_SRC:%.c=%.o)
vtinfo := OBJS = $(VTINFO_OBJ)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.ctf

CFLAGS += $(CCVERBOSE)
CERRWARN += $(CNOWARN_UNINIT)

vtdaemon := LDLIBS += -lpam -lbsm

.KEEP_STATE:

all: $(PROG)

vtdaemon: $(VTDAEMON_OBJ)
	$(LINK.c) -o $@ $(VTDAEMON_OBJ) $(LDLIBS)
	$(POST_PROCESS)

vtinfo: $(VTINFO_OBJ)
	$(LINK.c) -o $@ $(VTINFO_OBJ) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTLIBPROG)

clean:
	-$(RM) $(VTDAEMON_OBJ) $(VTINFO_OBJ)

include ../Makefile.targ
