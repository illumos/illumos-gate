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
# Copyright (c) 2001 by Sun Microsystems, Inc.
# All rights reserved.
#
# cmd/cmd-inet/etc/ike/Makefile
#

IKEDIR=		ike
PUBLICKEYDIR=	publickeys
CRLDIR=		crls
ETCPROG=	config.sample

include ../../../Makefile.cmd

ETCINETIKEDIR=	$(ROOTETC)/inet/$(IKEDIR)
ETCINETPUBLICKEYDIR=	$(ROOTETC)/inet/$(IKEDIR)/$(PUBLICKEYDIR)
ETCINETCRLDIR=	$(ROOTETC)/inet/$(IKEDIR)/$(CRLDIR)
ETCINETIKEPROG=	$(ETCPROG:%=$(ETCINETIKEDIR)/%)

FILEMODE=	0444
OWNER=		root
GROUP=		sys

.KEEP_STATE:

all:		$(ETCPROG)

install:	all $(ETCINETIKEDIR) $(ETCINETPUBLICKEYDIR) $(ETCINETIKEPROG) \
		$(ETCINETCRLDIR)

$(ETCINETIKEDIR)/% : %
		$(INS.file)

$(ETCINETIKEDIR):
		$(INS.dir)

$(ETCINETPUBLICKEYDIR) $(ETCINETCRLDIR):
		$(INS.dir)

FRC:

clean clobber lint:
