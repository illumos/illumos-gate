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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# On a 4.x machine (fourdotx), point ROOT at the header files you're using,
# and do:
#
#	% sccs edit ld.so
#	% make -f Makefile.4.x all
#	<test it a lot>
#	% sccs delget ld.so
#
# Unfortunately, at least <sys/isa_defs.h>, <sys/feature_tests.h> and <libelf.h>
# contain an '#error' line that makes the 4.x cpp choke (even though it
# shouldn't parse the error clause).  You may need to delete the '#' sign to
# compile each object.

OBJS=	rtldlib.o rtld.4.x.o rtsubrs.o div.o umultiply.o rem.o zero.o

all:	${OBJS}
	ld -o ld.so -Bsymbolic -assert nosymbolic -assert pure-text ${OBJS}

%.o:%.s
	as -k -P -I$(ROOT)/usr/include -D_SYS_SYS_S -D_ASM $<
	mv -f a.out $*.o

%.o:%.c
	cc -c -O -I$(ROOT)/usr/include -pic -D_NO_LONGLONG $<
