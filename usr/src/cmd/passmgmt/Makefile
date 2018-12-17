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
# Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright (c) 2018, Joyent, Inc.


PROG= 		passmgmt
FILE= 		datemsk
TXTS= 		$(FILE)

include ../Makefile.cmd

FILEMODE= 	0555
ROOTFILE=	$(ROOTETC)/$(FILE)

# conditional assignment
$(ROOTFILE):=	FILEMODE= $(LIBFILEMODE)

.KEEP_STATE:

LDLIBS +=	-lsecdb -lnsl
CERRWARN +=	-_gcc=-Wno-type-limits
CERRWARN +=	-_gcc=-Wno-implicit-function-declaration
CERRWARN +=	-_gcc=-Wno-uninitialized

# not linted
SMATCH=off

all: $(PROG) $(TXTS)

XGETFLAGS= -a -x $(PROG).xcl 

install: all $(ROOTLIBPROG) $(ROOTFILE)

# datemsk is generated from datemsk.template because of a side-effect of
# SCCS.  Some of the datemsk format strings include "%<letter>%", which
# SCCS confuses for ID keywords.  datemsk.template should quote the "%"
# with "\" and code below will filter out the "\".  Only datemsk format
# strings next to each other need to be quoted.

datemsk: datemsk.template
	@while read i; do echo $$i; done < datemsk.template > $@

clean:
	$(RM) datemsk

lint:	lint_PROG

include ../Makefile.targ
