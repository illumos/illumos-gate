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

MINCONN =	minconn.so
PASSPROMPT = 	passprompt.so
PPPOE =		pppoe.so

LIBRARIES =	minconn.so passprompt.so pppoe.so
OBJECTS =	minconn.o passprompt.o pppoe.o

# The rest of the sources are GPL
LINTSRCS =	pppoe.c

include		$(SRC)/lib/Makefile.lib
include		../Makefile.def

# Express objects in terms of "pics" thus triggering the appropriate CPPFLAGS,
# CFLAGS and DYNFLAGS settings from lib/Makefile.lib to build shared objects.
$(MINCONN):=	PICS = pics/minconn.o
$(PASSPROMPT):=	PICS = pics/passprompt.o
$(PPPOE):=	PICS = pics/pppoe.o

# Suppress -h setting from DYNFLAGS as these libraries aren't linked against.
# Establish external references through mapfiles and dependencies to allow
# use of -zdefs.
HSONAME=
$(MINCONN):=	MAPFILES = mapfile-minconn
$(PASSPROMPT):=	MAPFILES = mapfile-passprompt
$(PPPOE):=	MAPFILES = mapfile-pppoe

# A bug in pmake causes redundancy when '+=' is conditionally assigned, so
# '=' is used with extra variables.
XXXLDLIBS =
$(PASSPROMPT):=	XXXLDLIBS = -lc
LDLIBS +=	$(XXXLDLIBS)

CPPFLAGS +=	-I.. -I$(SRC)/uts/common
# XX64 -- this should not be needed -- fix me
DYNFLAGS +=	-_gcc=-nostdlib

CLOBBERFILES +=	$(LIBRARIES)

LIBPPPPLUGIN=	$(LIBRARIES:%=$(LIBPPPPLUGINDIR)/%)

$(LIBPPPPLUGIN):=	FILEMODE = 0544

$(LIBPPPPLUGINDIR):=	FILEMODE = 0755

# This is needed because install doesn't handle -g well.
UTILDIR=	$(ROOT)/usr/share/src/ppputil
ROOTSRC=	$(UTILDIR)/plugins
SRCFILES=	Makefile minconn.c passprompt.c pppd.h
ROOTSRCFILES=	$(SRCFILES:%=$(ROOTSRC)/%)
$(ROOTSRCFILES):=	FILEMODE= 0444

.KEEP_STATE:

all:	$(LIBRARIES)

$(MINCONN): pics .WAIT $$(PICS)
	$(BUILD.SO)
	$(POST_PROCESS_SO)

$(PASSPROMPT): pics .WAIT $$(PICS)
	$(BUILD.SO)
	$(POST_PROCESS_SO)

$(PPPOE): pics .WAIT $$(PICS)
	$(BUILD.SO)
	$(POST_PROCESS_SO)

install: all $(LIBPPPPLUGINDIR) $(LIBPPPPLUGIN) install_src

$(LIBPPPPLUGINDIR):
	$(INS.dir)

$(LIBPPPPLUGINDIR)/%:	%
	$(INS.file)

$(UTILDIR) $(ROOTSRC):
	$(INS.dir)

$(ROOTSRC)/Makefile%: Makefile%.dist
	$(INS.rename)

$(ROOTSRC)/%.h: ../%.h
	$(INS.file)

$(ROOTSRC)/%: %
	$(INS.file)

install_src:	$(UTILDIR) .WAIT $(ROOTSRC) .WAIT $(ROOTSRCFILES)

lint:
	$(LINT.c) $(LINTSRCS) $(LDLIBS)

include $(SRC)/lib/Makefile.targ
