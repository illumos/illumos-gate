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
# cmd/cmd-inet/etc/secret/Makefile
#

SECRETDIR=	secret
PRIVATEKEYDIR=	ike.privatekeys
ETCPROG=	ike.preshared ipseckeys.sample

include ../../../Makefile.cmd

ETCINETSECRETDIR=	$(ROOTETC)/inet/$(SECRETDIR)
ETCINETPRIVATEKEYDIR=	$(ROOTETC)/inet/$(SECRETDIR)/$(PRIVATEKEYDIR)
ETCINETSECRETPROG=	$(ETCPROG:%=$(ETCINETSECRETDIR)/%)

# Be extra paranoid about /etc/inet/secret
$(ETCINETSECRETDIR):=	DIRMODE=	700
$(ETCINETPRIVATEKEYDIR):=	DIRMODE=	700

DIRMODE=	700
FILEMODE=	600
OWNER=		root
GROUP=		sys

.KEEP_STATE:

all:		$(ETCPROG)

install:	all $(ETCINETSECRETDIR) $(ETCINETPRIVATEKEYDIR) $(ETCINETSECRETPROG)

$(ETCINETSECRETDIR)/% : %
		$(INS.file)

$(ETCINETSECRETDIR):
		$(INS.dir)

$(ETCINETPRIVATEKEYDIR):
		$(INS.dir)

FRC:

clean clobber lint:
