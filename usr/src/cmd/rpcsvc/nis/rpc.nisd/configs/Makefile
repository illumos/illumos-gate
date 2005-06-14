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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 2001 by Sun Microsystems, Inc.
# All rights reserved.
#
#	cmd/rpcsvc/nis/rpc.nisd/configs/Makefile

ETCDEFAULTFILES=	rpc.nisd
VARNISFILES=		NIS+LDAPmapping.template

include $(SRC)/cmd/Makefile.cmd

ROOTVARNIS=		$(ROOT)/var/nis
ROOTVARNISFILES=	$(VARNISFILES:%=$(ROOTVARNIS)/%)
ROOTETCDEFAULTFILES=	$(ETCDEFAULTFILES:%=$(ROOTETC)/default/%)

FILEMODE=	644
OWNER=		root
GROUP=		sys

all: FRC

install: all $(ROOTDIRS) $(ROOTETCDEFAULTFILES) $(ROOTVARNISFILES)

$(ROOTDIRS):
	$(INS.dir)

clean: FRC

clobber: FRC

lint: FRC

$(ROOTVARNIS)/NIS+LDAPmapping.template: NIS+LDAPmapping.template
	$(INS.file) NIS+LDAPmapping.template

$(ROOTETC)/default/rpc.nisd: rpc.nisd
	$(INS.file) rpc.nisd

FRC:
