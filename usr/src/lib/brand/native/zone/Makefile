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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

PROG=		sw_support
BRAND=		native
PROGS=		attach_update $(PROG)
XMLDOCS=	config.xml platform.xml
TEMPLATES=	SUNWdefault.xml SUNWblank.xml
CLOBBERFILES=	$(ROOTPROGS) $(ROOTXMLDOCS) $(ROOTTEMPLATES)

all:	$(PROGS)

include $(SRC)/cmd/Makefile.cmd
include ../../Makefile.brand

CPPFLAGS +=	-I/usr/include/libxml2 -D_REENTRANT
LDLIBS += -lzonecfg -luutil

POFILES=	$(PROGS:%=%.po)
POFILE=		native_zone.po

$(POFILE): $(POFILES)
	$(RM) $@
	$(BUILDPO.pofiles)

_msg: $(MSGDOMAINPOFILE)

lint: lint_PROG

install: $(PROGS) $(ROOTPROGS) $(ROOTXMLDOCS) $(ROOTTEMPLATES)

clean:
	-$(RM) $(PROGS)

include $(SRC)/Makefile.msg.targ
include $(SRC)/cmd/Makefile.targ
