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
# cmd/expand/Makefile 
#

PROG=		expand  unexpand
SRCS=		$(PROG:=.c)

include		../Makefile.cmd

# workaround two meanings for expand.po
POFILES= expand_cmd.po unexpand.po
POFILE= expand.po

CLOBBERFILES += expand_cmd.c

.KEEP_STATE:

all: $(PROG) 

install: all $(ROOTPROG)

clean:

lint:
	$(LINT.c) expand.c $(LDLIBS)
	$(LINT.c) unexpand.c $(LDLIBS)

$(POFILE): $(POFILES)
	$(RM) $@; cat $(POFILES) > $@

expand_cmd.c:
	$(RM) $@; cp expand.c $@

include ../Makefile.targ
