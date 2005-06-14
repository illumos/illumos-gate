#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/cmd-inet/usr.bin/pppd/plugins/Makefile
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
$(MINCONN):=	MAPFILE = mapfile-minconn
$(PASSPROMPT):=	MAPFILE = mapfile-passprompt
$(PPPOE):=	MAPFILE = mapfile-pppoe

# A bug in pmake causes redundancy when '+=' is conditionally assigned, so
# '=' is used with extra variables.
XXXLDLIBS =
$(PASSPROMPT):=	XXXLDLIBS = -lc
LDLIBS +=	$(XXXLDLIBS)

CPPFLAGS +=	-I.. -I$(SRC)/uts/common
# XX64 -- this should not be needed -- fix me
$(INTEL_BLD)DYNFLAGS +=	-_gcc=-nostdlib
DYNFLAGS +=	-M$(MAPFILE)

CLOBBERFILES +=	$(LIBRARIES)

LIBPPPPLUGIN=	$(LIBRARIES:%=$(LIBPPPPLUGINDIR)/%)

$(LIBPPPPLUGIN):=	FILEMODE = 0544
$(LIBPPPPLUGIN):=	OWNER = root
$(LIBPPPPLUGIN):=	GROUP = bin

$(LIBPPPPLUGINDIR):=	FILEMODE = 0755
$(LIBPPPPLUGINDIR):=	OWNER = root
$(LIBPPPPLUGINDIR):=	GROUP = bin

# This is needed because install doesn't handle -g well.
UTILDIR=	$(ROOT)/usr/share/src/ppputil
$(UTILDIR):=	OWNER = root
$(UTILDIR):=	GROUP = bin
ROOTSRC=	$(UTILDIR)/plugins
SRCFILES=	Makefile minconn.c passprompt.c pppd.h
ROOTSRCFILES=	$(SRCFILES:%=$(ROOTSRC)/%)
$(ROOTSRC):=	OWNER = root
$(ROOTSRC):=	GROUP = bin
$(ROOTSRCFILES):=	FILEMODE= 0444
$(ROOTSRCFILES):=	OWNER = root
$(ROOTSRCFILES):=	GROUP = bin

.KEEP_STATE:

all:	$(LIBRARIES)

$(MINCONN): pics .WAIT $$(MAPFILE) $$(PICS)
	$(BUILD.SO)
	$(POST_PROCESS_SO)

$(PASSPROMPT): pics .WAIT $$(MAPFILE) $$(PICS)
	$(BUILD.SO)
	$(POST_PROCESS_SO)

$(PPPOE): pics .WAIT $$(MAPFILE) $$(PICS)
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
