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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# This make file will build mech_krb5.so.1. This shared object
# contains all the functionality needed to support the Kereros V5 GSS-API
# mechanism. No other Kerberos libraries are needed.
#

include ../../../Makefile.master

SUBDIRS =	$(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

# include library definitions
include ../../Makefile.lib

GREP= find . \( -name SCCS -prune -o -name '*.[ch]' \) -print | sort | xargs grep

sparcv9_C_PICFLAGS =  -K PIC
TEXT_DOMAIN = SUNW_OST_NETRPC
POFILE = mech_krb5.po
POFILES = generic.po

HDRS=

CHECKHDRS= $(HDRS:%.h=%.check)

$(ROOTDIRS)/%:  %
	$(INS.file)

all :=          TARGET= all
clean :=        TARGET= clean
clobber :=      TARGET= clobber
install :=      TARGET= install
lint :=         TARGET= lint

.KEEP_STATE:

all clean lint:    $(SUBDIRS)

install: install_dir all .WAIT $(SUBDIRS)

# override ROOTLIBDIR and ROOTLINKS
ROOTLIBDIR=     $(ROOT)/usr/lib/gss

install_dir:	$(ROOTLIBDIR) $(BUILD64)

install_h:

clobber: $(SUBDIRS)
	$(RM) $(POFILE) $(POFILES)

check: $(CHECKHDRS)

do_pkg:
	cd pkg ; pwd ; $(MAKE) install

$(ROOTLIBDIR):
	$(INS.dir)


# include library targets
# include ../../Makefile.targ

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

_msg: $(MSGDOMAIN) .WAIT $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

$(POFILE): $(DERIVED_FILES) .WAIT $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

generic.po: FRC
	$(RM) messages.po
	-$(XGETTEXT) $(XGETFLAGS) `$(GREP) -s -l gettext`
	$(SED) "/^domain/d" messages.po > $@
	$(RM) messages.po

$(MSGDOMAIN):
	$(INS.dir)
