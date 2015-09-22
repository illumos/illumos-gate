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
# Copyright 2015 Nexenta Systems, Inc. All rights reserved.
#

PROG= uuidgen

include ../Makefile.cmd

CFLAGS +=	$(CCVERBOSE)
LDLIBS += -luuid

C99MODE = $(C99_ENABLE) 

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTPROG)

clean:

lint:	lint_PROG

include ../Makefile.targ
