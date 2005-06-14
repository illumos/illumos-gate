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
# Copyright (c) 2000 by Sun Microsystems, Inc.
# All rights reserved.
#
# cmd/cmd-inet/etc/ppp/Makefile
#

PPPDIR=		ppp
PEERSDIR=	peers
ETCPROGROOT=	pap-secrets	chap-secrets
ETCPROG=	options.tmpl options.ttya.tmpl myisp-chat.tmpl
ETCPEERS=	myisp.tmpl

include ../../../Makefile.cmd

ETCPPPDIR=	$(ROOTETC)/$(PPPDIR)
ETCPEERSDIR=	$(ETCPPPDIR)/$(PEERSDIR)
ETCPPPPROG=	$(ETCPROG:%=$(ETCPPPDIR)/%) $(ETCPEERS:%=$(ETCPEERSDIR)/%)
ETCPPPPROGROOT=	$(ETCPROGROOT:%=$(ETCPPPDIR)/%)

OWNER=		root
GROUP=		sys

# This is here to allow the make command to override this value;
# setting it to 0644 simplifies packaging.
SECRETSMODE=	0600

$(ETCPPPPROG)		:=	FILEMODE = 0644
$(ETCPPPPROGROOT)	:=	FILEMODE = $(SECRETSMODE)

.KEEP_STATE:

all:

install:	all $(ETCPPPDIR) $(ETCPEERSDIR) \
		$(ETCPPPPROG) $(ETCPPPPROGROOT)

$(ETCPPPDIR)/% : %
		$(INS.file)

$(ETCPPPDIR):
		$(INS.dir)

$(ETCPEERSDIR)/% : %
		$(INS.file)

$(ETCPEERSDIR):
		$(INS.dir)

FRC:

clean clobber lint:
