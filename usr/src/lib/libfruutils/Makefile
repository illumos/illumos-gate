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
# Copyright (c) 2000 by Sun Microsystems, Inc.
# All rights reserved.
#

# include library definitions
include $(SRC)/lib/Makefile.lib

SUBDIRS= $(MACH) $(BUILD64) $(MACH64)

# conditional assignments
all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
_msg :=		TARGET= _msg

POFILE=		libfruutils.po

.KEEP_STATE:

all install clean clobber: $(SUBDIRS)

_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

$(POFILE):
	$(RM) $@ messages.po
	$(XGETTEXT) $(XGETFLAGS) */*.[ch]*
	$(SED) -e '/^# msg/d' -e '/^domain/d' messages.po > $@
	$(RM) messages.po

$(MSGDOMAIN):
	$(INS.dir)

clobber:  po_clean

po_clean:
	$(RM) $(POFILE)

$(MACH) $(MACH64): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
