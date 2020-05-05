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

LIBRARY= libtsalarm.a
VERS= .1

# PLATFORM_OBJECTS is defined in platform Makefile
OBJECTS= $(PLATFORM_OBJECTS)

include $(SRC)/lib/Makefile.lib
include $(SRC)/Makefile.psm

SRCDIR =	../common

CPPFLAGS +=	-I../../libpcp/common

LINKED_DIRS	= $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%)
LINKED_LIB_DIRS	= $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib)
LINKED_LIBTSALARM_DIR	= \
	$(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib/libtsalarm.so)
LINKED_LIBTSALARM1_DIR	= \
	$(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib/libtsalarm.so.1)
LINKED_INCL_DIRS = $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/include)

LIBS = $(DYNLIB)
CFLAGS +=	$(CCVERBOSE)
LDLIBS +=	-L$(USR_PLAT_DIR)/$(PLATFORM)/lib -lpcp -lc
DYNFLAGS +=	-R/usr/platform/$(PLATFORM)/lib
PLATLIBS =	$(USR_PLAT_DIR)/$(PLATFORM)/lib
INS.slink6=	$(RM) -r $@; $(SYMLINK) ../../$(PLATFORM)/lib/libtsalarm.so.1 $@
INS.slink7=	$(RM) -r $@; $(SYMLINK) ../../$(PLATFORM)/lib/libtsalarm.so $@
INS.slink8=	$(RM) -r $@; $(SYMLINK) ../$(PLATFORM)/include $@

.KEEP_STATE:

all:	$(LIBS)

include $(SRC)/lib/Makefile.targ
