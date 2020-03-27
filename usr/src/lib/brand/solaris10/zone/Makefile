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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROGS =		attach clone detach image_install p2v postattach poststate \
		prestate preuninstall s10_boot uninstall
XMLDOCS=	config.xml platform.xml smf_disable.lst pkgrm.lst common.ksh \
		version
USERFILES=	smf_disable.conf pkgrm.conf
TEMPLATES =	SUNWsolaris10.xml
CLOBBERFILES=	$(ROOTPROGS) $(ROOTXMLDOCS) $(ROOTTEMPLATES) $(ETCUSER)

include $(SRC)/cmd/Makefile.cmd
include ../Makefile.s10

.KEEP_STATE:

all:	$(PROGS)

POFILES =	$(PROGS:%=%.po) common.po
POFILE =	s10_zone.po

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

install: $(PROGS) $(ROOTPROGS) $(ROOTXMLDOCS) $(ROOTTEMPLATES) $(ETCUSER)


clean:
	-$(RM) $(PROGS) $(POFILES) $(POFILE)

include $(SRC)/cmd/Makefile.targ
