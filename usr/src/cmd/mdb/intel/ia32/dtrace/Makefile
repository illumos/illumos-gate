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
#ident	"%Z%%M%	%I%	%E% SMI"

MODULE = dtrace.so
MDBTGT = kvm

MODSRCS = dtrace.c

include ../../../../Makefile.cmd
include ../../Makefile.ia32
include ../../../Makefile.module

#
# The dtrace dmod isn't currently built for kmdb.
#
MODULE_BUILD_TYPE = mdb

#
# This is unfortunately necessarily to be able to include mdb_param.h.
# See the optimistic comment in genunix's Makefile about how this is a
# "temporary" kludge.
#
CPPFLAGS += -I$(SRC)/uts/i86pc

#
# Until mdb itself links with libdtrace.so, the dtrace.so module needs to
# pull in libdtrace.so.
#
LDLIBS	+= -ldtrace -lm
