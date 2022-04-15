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
# Copyright (c) 2018, Joyent, Inc.

LIBRARY =	libhal-storage.a
VERS =		.1.0.0
VERS_MAJ =	.1
OBJECTS =	libhal-storage.o
PCFILE =	hal-storage.pc

include ../../Makefile.com

LIBS =		$(DYNLIB)
LDLIBS +=	-lc -ldbus-1 -lhal
NATIVE_LIBS +=	libdbus-1.so

SRCDIR =	../common

CFLAGS +=	$(CCVERBOSE)
CFLAGS +=	-_gcc=-Wno-deprecated-declarations
CFLAGS64 +=	-_gcc=-Wno-deprecated-declarations
CPPFLAGS +=	-DGETTEXT_PACKAGE=\"$(HAL_GETTEXT_PACKAGE)\" -DENABLE_NLS
CPPFLAGS +=	-DPACKAGE_LOCALE_DIR=\"/usr/lib/locale\"
CPPFLAGS +=	-I$(ROOT)/usr/include/hal

SMOFF += all_func_returns

ROOTMAJLINK =	$(ROOTLIBDIR)/$(LIBRARY:.a=.so)$(VERS_MAJ)
ROOTMAJLINK64 =	$(ROOTLIBDIR64)/$(LIBRARY:.a=.so)$(VERS_MAJ)

.KEEP_STATE:

all:		$(LIBS)

$(ROOTMAJLINK):
	-$(RM) $@; $(SYMLINK) $(DYNLIB) $@

$(ROOTMAJLINK64):
	-$(RM) $@; $(SYMLINK) $(DYNLIB) $@

include $(SRC)/lib/Makefile.targ
