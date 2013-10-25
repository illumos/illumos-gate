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

PROG	  = findunref
MAN1FILES = findunref.1
CFLAGS += $(CCVERBOSE)
LINTFLAGS += -ux

include ../Makefile.tools

CERRWARN += -_gcc=-Wno-unused
CERRWARN += -_gcc=-Wno-parentheses

$(ROOTONBLDMAN1FILES) := FILEMODE=      644

EXCEPTION_SRC= common open
EXCEPTION_LISTS=	$(EXCEPTION_SRC:%=exception_list.%)

CLOBBERFILES += exception_list

.KEEP_STATE:

all:    $(PROG) exception_list

install: all .WAIT $(ROOTONBLDMACHPROG) $(ROOTONBLDMAN1FILES)

lint:	lint_PROG

exception_list: $(EXCEPTION_LISTS)
	-$(RM) $@
	$(CAT) $(EXCEPTION_LISTS) > $@

clean:

include ../Makefile.targ
