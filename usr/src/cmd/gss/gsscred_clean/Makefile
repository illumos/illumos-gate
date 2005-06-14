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
# Copyright (c) 1998 by Sun Microsystems, Inc.
# All rights reserved.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/gss/gsscred_clean/Makefile
#

PROG=	gsscred_clean

SRCS=	gsscred_clean.ksh


include ../../Makefile.cmd

#
# Override $ROOTLIB
#
ROOTLIB=	$(ROOT)/usr/lib/gss

DIRS=	$(ROOTLIB)


#
# Override $FILEMODE
#
FILEMODE=744


#
# Set owner to root since it is executed out of crontab by root
#
OWNER=root
GROUP=sys


.KEEP_STATE:

#
# Rule for ksh files
#
.SUFFIXES:	.ksh

.ksh:
	$(RM) $@
	cat $< > $@
	chmod +x $@


all: $(PROG)

$(ROOTLIB):
	$(INS.dir)

$(ROOTLIB)/%:	%
	$(INS.file)

install: all $(DIRS) $(ROOTLIBPROG)

clean:

clobber:

lint:

include ../../Makefile.targ
