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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Copyright 2014 Joyent, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROGS =	lx_install lx_distro_install lx_init_zone lx_boot
PROGS += lx_init_zone_debian lx_init_zone_redhat lx_init_zone_ubuntu
PROGS += lx_networking lx_boot_zone_ubuntu
SUBDIRS = distros
XMLDOCS =	config.xml platform.xml
TEMPLATES =	SUNWlx.xml SUNWlx26.xml

all:	$(PROGS)

include $(SRC)/cmd/Makefile.cmd
include ../Makefile.lx

all :=		TARGET= all
install :=	TARGET= install
clobber :=	TARGET= clobber

POFILES=	$(PROGS:%=%.po)
POFILE=		lx_zone.po

$(POFILE): $(POFILES)
	$(RM) $@
	$(BUILDPO.pofiles)

_msg: $(MSGDOMAINPOFILE)

install: $(PROGS) $(ROOTXMLDOCS) $(ROOTTEMPLATES) $(ROOTPROGS) $(SUBDIRS)

lint:

clean:
	-$(RM) $(PROGS)

clobber: clean $(SUBDIRS)
	-$(RM) $(ROOTXMLDOCS) $(ROOTPROGS) $(ROOTTEMPLATES)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include $(SRC)/Makefile.msg.targ
