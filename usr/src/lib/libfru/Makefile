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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# lib/libfru/Makefile
#

include	$(SRC)/lib/Makefile.lib

SUBDIRS_i386 = libfrureg $(MACH)
$(BUILD64)SUBDIRS_i386 += $(MACH64)
SUBDIRS_sparc = libfrureg $(MACH)
$(BUILD64)SUBDIRS_sparc += $(MACH64)
SUBDIRS_i386 += .WAIT libnvfru libfruraw conf
SUBDIRS_sparc += .WAIT libfrupicl libfrupicltree libnvfru libfruraw

SUBDIRS = $(SUBDIRS_$(MACH))



# conditional assignments
all :=		TARGET= all
install :=      TARGET= install
clean :=        TARGET= clean
clobber :=      TARGET= clobber
_msg :=         TARGET= _msg

POFILE=		libfru.po

.KEEP_STATE:

all install clean clobber: $(SUBDIRS)

_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

$(POFILE):
	$(RM) $@ messages.po
	$(XGETTEXT) $(XGETFLAGS) *.[ch]* */*.[ch]*
	$(SED) -e '/^# msg/d' -e '/^domain/d' messages.po > $@
	$(RM) messages.po

$(MSGDOMAIN):
	$(INS.dir)

clobber:  po_clean

po_clean:
	$(RM) $(POFILE)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

install_h check: $(CHECKHDRS)
	@cd libnvfru; pwd; $(MAKE) $@

FRC:
