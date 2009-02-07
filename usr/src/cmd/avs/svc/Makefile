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

include ../../Makefile.cmd

XML = nws_scm.xml nws_sv.xml nws_ii.xml nws_rdc.xml nws_rdcsyncd.xml
SHFILES = $(XML)

all	:=	TARGET= all
install	:=	TARGET= install
clean	:=	TARGET= clean
clobber	:=	TARGET= clobber
lint	:=	TARGET= lint

ROOTSVCSYSFILES = $(XML:%=$(ROOTSVCSYSTEM)/%)

.KEEP_STATE:

.PARALLEL: $(OBJS)

all:	$(SHFILES)

lint:

install: all $(ROOTLIBSHFILES) $(ROOTSVCSYSFILES)

clean:
	$(RM) *.xml

$(SHFILES): $(XML:%=manifest/%)
	$(RM) $(@F)
	$(CP) $(@F:%=manifest/%) .

OWNER = root
GROUP = sys
FILEMODE = 0444

$(ROOTLIBSHFILES): $(SHFILES)
	$(INS.file)  $(@F)

$(ROOTSVCSYSFILES): $(SHFILES) $(ROOTLIBSHFILES)
	-$(RM) $@; $(LN) $(@F:%=$(ROOTLIB)/%) $@

FRC:

include ../../Makefile.targ
