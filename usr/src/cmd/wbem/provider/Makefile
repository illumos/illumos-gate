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
# Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/wbem/provider/Makefile
#

# include global definitions
include $(SRC)/cmd/wbem/Makefile.wbem

SUBDIRS= com tools c
POSUBDIRS= c

# make only these for 'check'
CHECK_SUBDIRS=	com c

# make only these for 'lint'
LINT_SUBDIRS=	tools c

all:=		TARGET=	all
install:=	TARGET=	install
clean:=		TARGET=	clean
clobber:=	TARGET=	clobber
check:=		TARGET=	check
lint:=		TARGET= lint
_msg:=		TARGET= _msg

.KEEP_STATE:

all install clean clobber: $(SUBDIRS)

_msg: $(POSUBDIRS)

lint: $(LINT_SUBDIRS)

check:	$(CHECK_SUBDIRS)

$(SUBDIRS) : FRC
	cd $@; pwd; $(MAKE) $(TARGET)

FRC:
