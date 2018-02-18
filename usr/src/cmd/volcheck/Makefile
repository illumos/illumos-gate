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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG =		volcheck
LOCAL_OBJS =	volcheck.o
RMVOLMGR_OBJS =	rmm_common.o vold.o
OBJS =		$(LOCAL_OBJS) $(RMVOLMGR_OBJS)
LOCAL_SRCS =	$(LOCAL_OBJS:%.o=%.c)
RMVOLGMR_SRCS =	$(RMVOLMGR_OBJS:%.o=$(SRC)/cmd/rmvolmgr/%.c)
SRCS =		$(LOCAL_SRCS) $(RMVOLMGR_SRCS)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/hal/Makefile.hal

LDLIBS +=	-ldbus-1 -ldbus-glib-1 -lglib-2.0 -lhal -lhal-storage -lcontract

CPPFLAGS +=	$(HAL_DBUS_CPPFLAGS) $(HAL_GLIB_CPPFLAGS)
CPPFLAGS +=	-I$(ROOT)/usr/include/hal
CPPFLAGS +=	-I$(SRC)/cmd/rmvolmgr
CSTD =	$(CSTD_GNU99)

CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-unused-function

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $(PROG) $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTPROG)

rmm_common.o: $(SRC)/cmd/rmvolmgr/rmm_common.c $(SRC)/cmd/rmvolmgr/rmm_common.h
	$(COMPILE.c) -o $@ $(SRC)/cmd/rmvolmgr/rmm_common.c
	$(POST_PROCESS_O)

vold.o: $(SRC)/cmd/rmvolmgr/vold.c $(SRC)/cmd/rmvolmgr/vold.h
	$(COMPILE.c) -o $@ $(SRC)/cmd/rmvolmgr/vold.c
	$(POST_PROCESS_O)

clean:
	$(RM) $(OBJS)

include ../Makefile.targ
