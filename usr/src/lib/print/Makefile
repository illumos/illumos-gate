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
# Copyright 2012 OmniTI Computer Consulting, Inc.  All rights reserved.
# Use is subject to license terms.
#

include $(SRC)/Makefile.master

SUBDIRS = \
	libprint \
	libpapi-common \
	libpapi-dynamic \
	libpapi-lpd \
	libipp-core \
	libhttp-core \
	libpapi-ipp \
	libipp-listener

all :=                  TARGET = all
clean :=                TARGET = clean
clobber :=              TARGET = clobber
install :=              TARGET = install
install_h :=              TARGET = install_h
lint :=                 TARGET = lint

TEXT_DOMAIN=	SUNW_OST_OSLIB
POFILE= print-lib.po

.KEEP_STATE:

all:	$(TXTS) $(SUBDIRS)

#
# Each message catalog file is generated in each sub
# directory and copied to the usr/src/cmd/lp/ directory.
# Those message catalog files are consolidated into one
# message catalog file.  The consolidated one will be copied
# into the $(ROOT)/catalog/SUNW_OST_OSCMD/ directory.
#

_msg:	$(MSGDOMAIN)
	@$(RM) $(POFILE)
	$(XGETTEXT) -s `/bin/find . -type d -name SCCS -prune -o -type f -name '*.c' -print`
	@/bin/cat messages.po | sed '/domain/d' > $(POFILE)
	@$(RM) messages.po
	$(RM)  $(MSGDOMAIN)/$(POFILE)
	/bin/cp $(POFILE) $(MSGDOMAIN)

install: $(ROOTDIRS) $(ROOTSYMLINKDIRS) $(SUBDIRS)

install_h clean strip lint: $(SUBDIRS)

clobber: $(SUBDIRS) local_clobber

local_clobber:
	$(RM) $(CLOBBERFILES) $(POFILE)

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include $(SRC)/Makefile.msg.targ

# Dependencies
libpapi-dynamic:	libpapi-common
libpapi-lpd:		libpapi-dynamic
libipp-core:		libpapi-common
libpapi-ipp:		libpapi-common libipp-core libhttp-core
libipp-listener:	libpapi-dynamic libipp-core
mod_ipp:		libipp-listener
