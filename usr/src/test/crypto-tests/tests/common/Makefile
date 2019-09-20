#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright (c) 2012 by Delphix. All rights reserved.
# Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
# Copyright 2019 Joyent, Inc.
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.ctf
include $(SRC)/test/Makefile.com

BASEOBJS = testfuncs.o cryptotest_pkcs.o cryptotest_kcf.o
OBJS = $(BASEOBJS:%.o=%.32.o) $(BASEOBJS:%.o=%.64.o)
SRCS = $(OBJS:%.o=%.c)

CPPFLAGS += -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -I$(SRC)/common/crypto/

all install: $(OBJS)

%.32.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.64.o: %.c
	$(COMPILE64.c) -o $@ $<
	$(POST_PROCESS_O)

clobber clean:
	-$(RM) $(OBJS)
