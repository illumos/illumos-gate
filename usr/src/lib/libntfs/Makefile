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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
#

include		../Makefile.lib

SUBDIRS =	$(MACH)

all :=          TARGET= all
clean :=        TARGET= clean
clobber :=      TARGET= clobber
delete :=       TARGET= delete
install :=      TARGET= install
_msg :=		TARGET= _msg
package :=      TARGET= package

LIBRARY= 	libntfs.a
TEXT_DOMAIN=	SUNW_OST_OSLIB
XGETFLAGS=	-a
POFILE=		$(LIBRARY:.a=.po)
POFILES=	generic.po

SED=	sed
GREP=	grep

.KEEP_STATE:

all clean delete install package: $(SUBDIRS)
clobber: $(SUBDIRS)
	$(RM) $(CLOBBERFILES)

all install: THIRDPARTYLICENSE

CLOBBERFILES += THIRDPARTYLICENSE

THIRDPARTYLICENSE: $(SRC)/common/GPLDISCLAIMER COPYING
	$(RM) $@
	$(CAT) $(SRC)/common/GPLDISCLAIMER COPYING > $@

# definitions for install_h target
HDRS=		../common/include/ntfs/attrib.h \
		../common/include/ntfs/attrlist.h \
		../common/include/ntfs/bitmap.h \
		../common/include/ntfs/bootsect.h \
		../common/include/ntfs/collate.h \
		../common/include/ntfs/compat.h \
		../common/include/ntfs/compress.h \
		../common/include/ntfs/crypto.h \
		../common/include/ntfs/debug.h \
		../common/include/ntfs/device.h \
		../common/include/ntfs/device_io.h \
		../common/include/ntfs/dir.h \
		../common/include/ntfs/endians.h \
		../common/include/ntfs/index.h \
		../common/include/ntfs/inode.h \
		../common/include/ntfs/layout.h \
		../common/include/ntfs/lcnalloc.h \
		../common/include/ntfs/list.h \
		../common/include/ntfs/logfile.h \
		../common/include/ntfs/logging.h \
		../common/include/ntfs/mft.h \
		../common/include/ntfs/mst.h \
		../common/include/ntfs/ntfstime.h \
		../common/include/ntfs/runlist.h \
		../common/include/ntfs/security.h \
		../common/include/ntfs/support.h \
		../common/include/ntfs/types.h \
		../common/include/ntfs/unistr.h \
		../common/include/ntfs/version.h \
		../common/include/ntfs/volume.h
ROOTHDRDIR=     $(ROOT)/usr/include
ROOTHDRS=       $(HDRS:%=$(ROOTHDRDIR)/%)
CHECKHDRS=      $(HDRS:%.h=%.check)

# install rule for install_h target
$(ROOTHDRDIR)/%: %
	$(INS.file)

install_h: $(ROOTHDRS)

check: $(CHECKHDRS)

$(SUBDIRS):      FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

$(POFILE):	$(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

$(POFILES):
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) *.[ch]* */*.[ch]*
	$(SED) -e '/^# msg/d' -e '/^domain/d' messages.po > $@
	$(RM) messages.po

$(MSGDOMAIN):
	$(INS.dir)

FRC:
