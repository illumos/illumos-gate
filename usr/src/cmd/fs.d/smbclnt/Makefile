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
# Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
#

#
# cmd/fs.d/smbclnt/Makefile
#  contains the CIFS client commands
#

include $(SRC)/Makefile.master

SUBDIRS_CATALOG=	smbutil mount umount share
SUBDIRS=		$(SUBDIRS_CATALOG) chacl lsacl \
			smbiod smbiod-svc svc fksmbcl

# for messaging catalog files
#
POFILES=        smbutil/smbutil_all.po mount/mount.po umount/umount.po \
		share/share.po share/unshare.po
POFILE=         smbclnt.po

all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber
catalog:=       TARGET= catalog

.KEEP_STATE:

.PARALLEL:	$(SUBDIRS)

all install clean clobber: $(SUBDIRS)

catalog: $(SUBDIRS_CATALOG)
	$(RM) $(POFILE)
	cat $(POFILES) > $(POFILE)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
