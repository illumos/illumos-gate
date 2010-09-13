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

PROGS = dblfree exhaust align dirtymem general wideload failwide reallocs

all: ${PROGS}

dblfree: dblfree.c
	cc -o $@ -O $? -I../common -L../${MACH} -R../${MACH} -lmtmalloc

exhaust: exhaust.c
	cc -o $@ -O $? -I../common -L../${MACH} -R../${MACH} -lmtmalloc

align: align.c
	cc -o $@ -O $? -L../${MACH} -R../${MACH} -lmtmalloc

dirtymem: dirtymem.c
	cc -o $@ -O $? -I../common -L../${MACH} -R../${MACH} -lmtmalloc

general: general.c
	cc -o $@ -O $? -L../${MACH} -R../${MACH} -lmtmalloc

wideload: wideload.c
	cc -o $@ -O $? -L../${MACH} -R../${MACH} -lmtmalloc

failwide: failwide.c
	cc -o $@ -O $? -L../${MACH} -R../${MACH} -lmtmalloc

reallocs: reallocs.c
	cc -o $@ -O $? -L../${MACH} -R../${MACH} -lmtmalloc

clobber clean:
	rm -f ${PROGS} core
