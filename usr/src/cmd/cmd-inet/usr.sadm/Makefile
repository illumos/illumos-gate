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
# Copyright 1999-2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2014 Garrett D'Amore <garrett@damore.org>
#
# cmd/cmd-inet/usr.sadm/Makefile

SUBDIRS2=	scripts

include ../../Makefile.cmd

all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber
lint:=		TARGET= lint

.KEEP_STATE:

.PARALLEL: $(SUBDIRS1) $(SUBDIRS2)

all clean clobber lint: $(SUBDIRS1)

install: $(SUBDIRS1) $(SUBDIRS2)

$(SUBDIRS1) $(SUBDIRS2): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
