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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/fs.d/smbclnt/Makefile
#
#  cmd/fs.d/smbclnt contains the CIFS client commands
#

include $(SRC)/Makefile.master

SUBDIRS_CATALOG=	smbutil mount umount
SUBDIRS=		$(SUBDIRS_CATALOG) svc

# for messaging catalog files
#
POFILES=        smbutil/smbutil_all.po mount/mount.po umount/umount.po
POFILE=         smbclnt.po

all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber
lint:=		TARGET= lint
catalog:=       TARGET= catalog

.KEEP_STATE:

.PARALLEL:	$(SUBDIRS)

install clean clobber: $(SUBDIRS)

all lint catalog: $(SUBDIRS_CATALOG)
	$(RM) $(POFILE)
	cat $(POFILES) > $(POFILE)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
