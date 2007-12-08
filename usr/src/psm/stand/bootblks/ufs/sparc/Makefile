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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# psm/stand/bootblks/ufs/sparc/Makefile
#

BASEDIR = ../..

include $(BASEDIR)/Makefile.com

#
# This program is used to install the boot block
#
INSTALLBOOT		= installboot

USR			= $(ROOT)/usr
USR_SBIN		= $(USR)/sbin
USR_SBIN_INSTALLBOOT	= $(USR_SBIN)/$(INSTALLBOOT)

#
# Overrides for installing installboot.
#
INS.file.555		= $(RM) $@; $(INS) -s -m 555 -f $(@D) $<
$(CH)INS.file.555	= $(INS) -s -m 555 -u $(OWNER) -g $(GROUP) -f $(@D) $<


SUBDIRS	= sun4u sun4v

all	:=	TARGET= all
install	:=	TARGET= install
clean	:=	TARGET= clean
clobber	:=	TARGET= clobber
lint	:=	TARGET= lint

.KEEP_STATE:

all: $(INSTALLBOOT) $(SUBDIRS)

install: $(USR_SBIN_INSTALLBOOT) $(SUBDIRS)

lint clean: $(SUBDIRS)

clobber: $(SUBDIRS)
	-$(RM) $(INSTALLBOOT)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

#
# install rules
#
$(USR_SBIN)/%:	% $(USR_SBIN)
	$(INS.file.555)

#
# Pattern matching rules for source in this directory
#
%: %.sh
	$(RM) $@
	cat $< > $@
	chmod +x $@
