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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# lib/gss_mechs/mech_dh/backend/Makefile
#
PROTOCOL_DIR = mech
SUBDIRS = $(MACH) $(BUILD64) $(MACH64)

PROTO_FILE = dhmech_prot.x
DERIVED_FILES = mech/dhmech_prot.h mech/xdr_token.c
CLEANFILES += $(DERIVED_FILES)

# include library definitions
include ../../../Makefile.lib

TEXT_DOMAIN =	SUNW_OST_NETRPC
POFILES =	generic.po
POFILE = mech_dh.po

SED=    sed
GREP=   grep

all :=          TARGET= all
clean :=        TARGET= clean
clobber :=      TARGET= clobber
delete :=       TARGET= delete
install :=      TARGET= install
catalog :=      TARGET= catalog
package :=      TARGET= package
_msg :=		TARGET= _msg

.KEEP_STATE:
all:            $(DERIVED_FILES) .WAIT $(SUBDIRS)

install:        $(DERIVED_FILES) .WAIT $(SUBDIRS)

clean clobber delete catalog package:      $(SUBDIRS)

#
# Rules for building the derived files
#
mech/xdr_token.c: $(PROTOCOL_DIR)/dhmech_prot.x
	$(RPCGEN) -c $(PROTOCOL_DIR)/dhmech_prot.x |\
	$(SED) -e 's!$(PROTOCOL_DIR)/dhmech_prot.h!dhmech_prot.h!' > $@

mech/dhmech_prot.h: mech/dhmech_prot.x
	$(RPCGEN) -h $(PROTOCOL_DIR)/dhmech_prot.x > $@

# include library targets
include ../../../Makefile.targ

_msg: $(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

$(POFILE): $(DERIVED_FILES) .WAIT $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

generic.po:
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext mech/*.[ch]`
	$(SED) "/^domain/d" messages.po > $@
	$(RM) messages.po

$(MSGDOMAIN):
	$(INS.dir)

$(MACH) $(MACH64):      FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
