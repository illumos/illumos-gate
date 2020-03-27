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
# Copyright (c) 1995,1997, by Sun Microsystems, Inc.
# All rights reserved.
#
include ../../Makefile.master

SUBDIRS= $(MACH) $(BUILD64) $(MACH64)

# include library definitions
include ../Makefile.lib

#override INS.liblink
INS.liblink=	-$(RM) $@; $(SYMLINK) $(LIBLINKPATH)$(LIBLINKS)$(VERS) $@

HDRS=

CHECKHDRS= $(HDRS:%.h=%.check)

#install rule
$(ROOTDIRS)/%: %
	$(INS.file)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
_msg :=         TARGET= _msg

LIBRARY=	rpcsec.a
TEXT_DOMAIN=	SUNW_OST_NETRPC
XGETFLAGS=	-a
POFILE=		$(LIBRARY:.a=.po)
POFILES=	generic.po

.KEEP_STATE:

all: .WAIT $(SUBDIRS)

lint:   .WAIT $(SUBDIRS)

install: all .WAIT $(SUBDIRS)

install_h:

clean clobber:  $(SUBDIRS)

check: $(CHECKHDRS)

# include library targets
include ../Makefile.targ

$(MACH) $(MACH64):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

$(POFILE):	.WAIT $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

$(POFILES):
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext *.[ch]`
	$(SED) -e '/^# msg/d' -e '/^domain/d' messages.po > $@
	$(RM) messages.po

catalog:

$(MSGDOMAIN):
	$(INS.dir)

FRC:
