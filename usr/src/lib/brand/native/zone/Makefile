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

PROG=		sw_support
BRAND=		native
PROGS=		attach_update image_install p2v $(PROG)
XMLDOCS=	config.xml platform.xml smf_disable.lst pkgrm.lst
USERFILES=	smf_disable.conf pkgrm.conf
SHARED=		common.ksh query uninstall.ksh
TEMPLATES=	SUNWdefault.xml SUNWblank.xml
CLOBBERFILES=	$(ROOTPROGS) $(ROOTXMLDOCS) $(ROOTTEMPLATES) $(ROOTSHARED) \
	$(ETCUSER)

all:	$(PROGS)

include $(SRC)/cmd/Makefile.cmd
include ../../Makefile.brand

$(ROOTSHAREDDIR)/common.ksh := FILEMODE = 444
$(ROOTSHAREDDIR)/uninstall.ksh := FILEMODE = 444

CPPFLAGS +=	-I/usr/include/libxml2 -D_REENTRANT
LDLIBS += -lzonecfg -luutil

POFILES=	$(PROGS:%=%.po) common.po query.po uninstall.po
POFILE=		native_zone.po

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

lint: lint_PROG

install: $(PROGS) $(ROOTPROGS) $(ROOTXMLDOCS) $(ROOTTEMPLATES) $(ROOTSHARED) \
	$(ETCUSER)

clean:
	-$(RM) $(PROGS) $(POFILES) $(POFILE)

include $(SRC)/cmd/Makefile.targ
