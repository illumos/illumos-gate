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

BRAND=		sn1
PROGS=		sn1_boot
XMLDOCS=	config.xml platform.xml
TEMPLATES=	SUNWsn1.xml
CLOBBERFILES=	$(PROGS)

all:	$(PROGS)

include $(SRC)/cmd/Makefile.cmd
include ../../Makefile.brand

POFILES=	$(PROGS:%=%.po)
POFILE=		sn1_zone.po

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@


clean:
	-$(RM) $(PROGS) $(POFILES) $(POFILE)

install: $(PROGS) $(ROOTPROGS) $(ROOTXMLDOCS) $(ROOTTEMPLATES)

include $(SRC)/cmd/Makefile.targ
