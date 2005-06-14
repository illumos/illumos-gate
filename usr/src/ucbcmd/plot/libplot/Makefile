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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1989 by Sun Microsystems, Inc.
#
# include global definitions
include ../../../Makefile.master

SUBDIRS= aed bitgraph dumb gigi hp2648 hp7221 imagen plot \
		t300 t300s t4013 t4014 t450

all:=     TARGET= all
clean:=   TARGET= clean
clobber:= TARGET= clobber
install:= TARGET= install
lint:=    TARGET= lint

.KEEP_STATE:
all clean clobber lint:  $(SUBDIRS)

install:

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)


FRC:

