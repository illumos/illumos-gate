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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/vi/Makefile

SUBDIRS=	misc port
TXTS=		PRESERVE README
POFILES=        $(SUBDIRS:%=%/%.po)

include ../Makefile.cmd
#
# For message catalogue file
#
POFILE= vi.po

all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber
lint:=		TARGET= lint
_msg:=          TARGET= catalog

# this directory is made in ../../Targetdirs
ROOTINITD= $(ROOTETC)/init.d

ROOTLINK= $(ROOTETC)/rc2.d/S89PRESERVE

ETCINITF= PRESERVE
ROOTETCINITF= $(ETCINITF:%=$(ROOTINITD)/%)
$(ROOTETCINITF):=	FILEMODE =	744

$(ROOTINITD)/% : %
	$(INS.file)

.KEEP_STATE:

all:	$(SUBDIRS)

install: $(ETCINITF) $(SUBDIRS) $(ROOTETCINITF) $(ROOTLINK)

$(ROOTLINK): $(ROOTETCINITF)
	-$(RM) $@
	-$(LN) -f $(ROOTETCINITF) $@

clean lint: $(SUBDIRS)

clobber: $(SUBDIRS)	clobber_local

clobber_local:
	$(RM) $(CLOBBERFILES)

#
# For message catalogue file
#
_msg: $(SUBDIRS)
	$(RM) $(POFILE)
	cat $(POFILES) > $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	cp $(POFILE) $(MSGDOMAIN)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
