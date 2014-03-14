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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG= getconf
XPG4PROG= getconf
XPG6PROG= getconf
X4= objs.xpg4
X6= objs.xpg6
OBJS= getconf.o
XPG4EXOBJS= $(X4)/getconf.o
XPG6EXOBJS= $(X6)/getconf.o

include ../Makefile.cmd

XPG4EXOBJS += values-xpg4.o
CFLAGS += $(CCVERBOSE)
# XPG4
$(XPG4) := CFLAGS += -D_XOPEN_SOURCE -I$(SRC)/lib/libc/inc

# XPG6MODE:  Depending on the version of the compiler, the value of
# __STDC_VERSION__ may differ even in the presence of the same compilation
# options. The default compilation mode for Sun compilers that support the
# C99 standard is -xc99=all,no_lib. C99MODE= is equivalent to -xc99=all,no_lib.
# This translates to C99 semantics without the C99 library specific behaviors
# and dependencies.
#
# For pre-5.7 compilers (unless patched with 117551-04 or 117552-05), in the
# default compilation mode, __STDC_VERSION__ was defined to be 199901L. For
# 5.7 and on compilers, __STDC_VERSION__ defaults to 199409L in order to 
# maintain source compatibility. Neither of these cases results in the 
# importing of /usr/lib/values-xpg6.o, so we need to either manually import 
# it via linking with a local version of the object, or set -xc99=%all which
# by default imports /usr/lib/values-xpg6.o. C99MODE=C99_ENABLE is equivalent
# to -xc99=all. If C99_ENABLE is defined and we also attempt to link with a 
# local version of values-xpg6.o, an error will occur due to multiple 
# definitions for __xpg4 and __xpg6. Because /usr/lib/values-xpg6.o was
# delivered in Solaris 10 and is a stable interface, there is no need to
# build and link with a local version of the object.
#
# The gcc compiler behaves differently and requires -std=gnu99.
#
# For XPG4, we need to link with a local version of values-xpg4.o because
# the compiler only imports this by default (from /usr/lib/values-xpg4.o)
# if we use the c89 utility as opposed to cc.

XPG6MODE = $(C99_ENABLE)
$(XPG6) := C99MODE = $(XPG6MODE)
$(XPG6) := CFLAGS += -D_XOPEN_SOURCE=600 -I$(SRC)/lib/libc/inc

.KEEP_STATE:

all: $(PROG) $(XPG4) $(XPG6)

$(PROG):	$(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

$(XPG4):	$(X4) $(XPG4EXOBJS)
	$(LINK.c) -o $@ $(XPG4EXOBJS) $(LDLIBS)
	$(POST_PROCESS)

$(XPG6):	$(X6) $(XPG6EXOBJS)
	$(LINK.c) -o $@ $(XPG6EXOBJS) $(LDLIBS)
	$(POST_PROCESS)


$(XPG4EXOBJS):	$(X4)


$(X4)/%.o:	%.c
	$(COMPILE.c) -o $@ $<


$(X4):
	-@mkdir -p $@


$(XPG6EXOBJS):	$(X6)


$(X6)/%.o:	%.c
	$(COMPILE.c) -o $@ $<


$(X6):
	-@mkdir -p $@


install: all $(ROOTPROG) $(ROOTXPG4PROG) $(ROOTXPG6PROG)

values-xpg4.o: ../../lib/common/common/values-xpg4.c
	$(COMPILE.c) -o $@ ../../lib/common/common/values-xpg4.c

clean:
	-@rm -rf $(OBJS) $(XPG4EXOBJS) $(XPG6EXOBJS) $(X4) $(X6) \
		$(PROG) $(XPG4) $(XPG6)

lint:	lint_PROG

include ../Makefile.targ
