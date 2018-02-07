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
# Use is subject to license terms.
#

PROG =		rmvolmgr
OBJS =		rmm_common.o rmvolmgr.o vold.o
SRCS =		$(OBJS:%.o=%.c)

MANIFEST =      rmvolmgr.xml
SVCMETHOD =     svc-rmvolmgr

include ../Makefile.cmd
include ../hal/Makefile.hal

POFILE=rmvolmgr_all.po
POFILES=$(OBJS:%.o=%.po)

LDLIBS +=	-ldbus-1 -ldbus-glib-1 -lglib-2.0 -lhal -lhal-storage -lcontract -lscf

CPPFLAGS +=	$(HAL_DBUS_CPPFLAGS) $(HAL_GLIB_CPPFLAGS)
CPPFLAGS +=	-I$(ROOT)/usr/include/hal
CSTD =	$(CSTD_GNU99)

CERRWARN += 	-_gcc=-Wno-switch
CERRWARN += 	-_gcc=-Wno-uninitialized
CERRWARN += 	-_gcc=-Wno-unused-variable
CERRWARN += 	-_gcc=-Wno-parentheses
CERRWARN += 	-_gcc=-Wno-unused-function

ROOTCMDDIR =		$(ROOTLIB)
ROOTMANIFESTDIR =	$(ROOTSVCSYSTEMFILESYSTEM)
$(ROOTMANIFEST) :=	FILEMODE = 444
$(ROOTLIBSVCMETHOD)/svc-rmvolmgr:= FILEMODE = 555

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $(PROG) $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTCMD) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

clean:
	$(RM) $(OBJS)

check: $(CHKMANIFEST)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

include ../Makefile.targ

