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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG=		sbcp

include ../Makefile.ucbcmd

CLEANFILES=	sysent.s
POFILE=

OBJS=		sbcp.o sbcp_util.o

FILEMODE=	755

.KEEP_STATE:

# Preserve the relationship of libraries as they are defined in libc.so.1.9
LIBBC=		../../lib/libbc/sparc/libc.so.1.9
LIBUCB=		../../ucblib/libucb/sparc/libucb.so.1

# need libc/sparc/inc for PIC.h
ASFLAGS=	-P -D_ASM -DPIC $(AS_PICFLAGS)
LDFLAGS=	-R /usr/4lib:/usr/ucblib -e _start -G -t \
		$(BLOCAL) $(ZNOVERSION) $(ZDEFS) $(ZTEXT) \
		-I/usr/lib/ld.so.1
LIBS=		$(LDLIBS.lib) -lmapmalloc $(LIBBC) $(LIBUCB) -lnsl -lc

CERRWARN	+= -_gcc=-Wno-unused-variable

all:	$(PROG)

install: all $(ROOT4LIBPROG)

clean:
	$(RM) $(OBJS) $(CLEANFILES)

$(PROG):	$(OBJS)
	$(LDOPTS) $(LD) $(LDFLAGS) -o sbcp $(OBJS) $(LIBS)
	$(POST_PROCESS)

$(OBJS):	sysent.s

sysent.s:	syscalls.list mksysent
	-$(RM) sysent.s
	sh ./mksysent > sysent.s

include ../Makefile.ucbtarg
