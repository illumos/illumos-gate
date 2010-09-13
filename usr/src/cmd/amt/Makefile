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
# Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/amt/Makefile
#

PROG=	amt

include ../Makefile.cmd

TEXT_DOMAIN=SUNW_OST_OSCMD
POFILE=$(PROG).po

$(64ONLY)SUBDIRS= $(MACH)
$(BUILD64)SUBDIRS += $(MACH64)
CLEANFILES  += $(POFILE)

SHFILERCS= $(PROG:%=%.sh)

all	:=	TARGET = all
install	:=	TARGET = install
clean	:=	TARGET = clean
clobber	:=	TARGET = clobber
lint	:=	TARGET = lint

.KEEP_STATE:

all:	$(SUBDIRS) pofile $(PROG)

clean clobber lint:	$(SUBDIRS)

install:	$(SUBDIRS) $(ROOTPROG)

pofile:	$(POFILE)

$(PROG):	$(PROG).sh
	$(RM) -f $(PROG)
	$(CP) $(PROG).sh $(PROG)
	$(CHMOD) 555 $(PROG)

$(POFILE):	$(SRCS)
	$(RM) $(TEXT_DOMAIN).po
	$(XGETTEXT) -s -d $(TEXT_DOMAIN) $<
	$(MV) $(TEXT_DOMAIN).po $@

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include ../Makefile.targ
