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
# Copyright 2018 Joyent, Inc.
#

PROG =			gen_errno

include ../../../../cmd/Makefile.cmd

OBJS =			gen_errno.o

CLOBBERFILES +=		$(PROG)

NATIVECC_CFLAGS +=	$(CFLAGS) $(CCVERBOSE)
# As evidenced by the use of the NATIVE_ variables, gen_errno is intended
# to be able to run on the build host.  We continue to link it against
# libcmdutils.so instead of libcustr.so in order to allow it to run on
# older build hosts (relying on the libcmdutil filter entries if run on
# newer hosts with libcustr.so).
NATIVECC_LDLIBS +=	-lcmdutils -lnvpair

.KEEP_STATE:

all: $(PROG)

install: all

lint:	lint_PROG

clean:
	$(RM) $(OBJS)

$(PROG): $(OBJS)
	$(NATIVECC) $(NATIVECC_CFLAGS) $(NATIVECC_LDLIBS) $(OBJS) -o $@
	$(POST_PROCESS)

include ../../../../cmd/Makefile.targ
