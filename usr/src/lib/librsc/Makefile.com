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
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

LIBRARY= librsc.a
VERS= .1

# PLATFORM_OBJECTS is defined in platform Makefile
OBJECTS= $(PLATFORM_OBJECTS)

include $(SRC)/lib/Makefile.lib
include $(SRC)/Makefile.psm

CPPFLAGS +=	$(PLATINCS)

LINKED_DIRS	= $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%)
LINKED_LIB_DIRS	= $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib)
LINKED_LIBRSC_DIR	= \
	$(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib/librsc.so)
LINKED_LIBRSC1_DIR	= \
	$(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib/librsc.so.1)

# There should be a mapfile here
MAPFILES =

SRCDIR =	common
LIBS = $(DYNLIB)
CFLAGS +=	$(CCVERBOSE)
LDLIBS +=	-lc
PLATLIBS =	$(USR_PLAT_DIR)/$(PLATFORM)/lib/
INS.slink6=	$(RM) -r $@; $(SYMLINK) ../../$(PLATFORM)/lib/librsc.so.1 $@
INS.slink7=	$(RM) -r $@; $(SYMLINK) ../../$(PLATFORM)/lib/librsc.so $@

.KEEP_STATE:

#
# build/lint rules
#
all:	$(LIBS)

#
# install rules
#
$(PLATLIBS)/librsc.so:
	$(RM) -r $@; $(SYMLINK) librsc.so.1 $@

install:	all $(USR_PSM_LIBS) $(PLATLIBS)/librsc.so \
		$(LINKED_DIRS) $(LINKED_LIB_DIRS) \
		$(LINKED_LIBRSC_DIR) $(LINKED_LIBRSC1_DIR)

$(USR_PSM_LIB_DIR)/%: % $(USR_PSM_LIB_DIR)
	$(INS.file)

$(LINKED_DIRS):	$(USR_PLAT_DIR)
	-$(INS.dir)

$(LINKED_LIB_DIRS):	$(LINKED_DIRS)
	-$(INS.dir)

$(LINKED_LIBRSC_DIR): $(USR_PLAT_DIR)
	-$(INS.slink7)

$(LINKED_LIBRSC1_DIR): $(USR_PLAT_DIR)
	-$(INS.slink6)

include $(SRC)/lib/Makefile.targ
