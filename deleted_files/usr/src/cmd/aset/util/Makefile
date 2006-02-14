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
# Copyright (c) 1991 by Sun Microsystems, Inc.
#
# cmd/aset/util/Makefile

PROG= geteuid homedir is_readable is_writable minmode realpath str_to_mode nls

SCRIPTS= addcksum file_attr taskstat

include ../../Makefile.cmd

SRCS= $(PROG:=.c)

# we assume Makefile above created ROOTDIR
ROOTDIR= $(ROOT)/usr/aset/util

ROOTPROG= $(PROG:%=$(ROOTDIR)/%)
ROOTSCRIPTS= $(SCRIPTS:%=$(ROOTDIR)/%)

DIRMODE= 700
FILEMODE= 700
OWNER= root

CLOBBERFILES= $(SCRIPTS)

# install rule
$(ROOTDIR)/%: %
	$(INS.file)

.KEEP_STATE:

all: $(PROG) $(SCRIPTS)

install: all $(ROOTPROG) $(ROOTSCRIPTS)

lint: lint_SRCS

clean:

include ../../Makefile.targ
