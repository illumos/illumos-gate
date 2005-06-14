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

LIBRARY=	libwrsmconf.a
VERS=		.1

CSRCS = confpack.c confprint.c wrsm_confpack.c libwrsmconf.c util.c
LINTSRCS = $(CSRCS:%=../%)
OBJECTS = $(CSRCS:%.c=%.o) confparse.tab.o confparse.yy.o

include ../../Makefile.lib

#
# This Makefile makes using CTF very tricky, so we just disable it
#
CTFCONVERT_POST = :
CTFMERGE_LIB = :

#
# Note:  We install this library in the root filesystem
# because it is needed by the /platform/sun4u/sbin/wrsmconf
# command, which is executed before /usr is mounted.
#
ROOTLIBDIR= $(ROOT)/platform/sun4u/lib
ROOTLIBDIR64= $(ROOT)/platform/sun4u/lib/sparcv9

LIBS = $(DYNLIB)

BUILD.SO=	$(CC) $(CFLAGS) -o $@ $(GSHARED) $(DYNFLAGS) $(OBJECTS) $(LDLIBS)

CLEANFILES=	$(OBJECTS) confparse.yy.c confparse.tab.c confparse.tab.h
CLOBBERFILES=	$(DYNLIB) $(LIBRARY) $(LINTLIB)

FILEMODE = 755

CPPFLAGS += -I$(ROOT)/usr/platform/sun4u/include -I.. -I. -DPIC
CFLAGS += $(C_PICFLAGS)
CFLAGS64 += $(C_PICFLAGS64)
LDLIBS += -lc

$(DYNLIB):	$(OBJECTS)
	$(BUILD.SO)
	$(POST_PROCESS_SO)

.KEEP_STATE:

%.o:	../%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

confparse.tab.c: ../confparse.y
	$(YACC) -b confparse -d ../confparse.y

confparse.yy.c: ../confparse.l
	$(LEX) -t ../confparse.l > confparse.yy.c

clean:
	-$(RM) $(CLEANFILES)

clobber: clean
	-$(RM) $(CLOBBERFILES)

lint: $(MACH)_lint

i386_lint:

sparc_lint:
	$(LINT.c) -m $(LINTSRCS) $(LDLIBS)
