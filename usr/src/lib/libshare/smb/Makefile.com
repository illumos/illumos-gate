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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
#

LIBRARY =	libshare_smb.a
VERS =		.1
SMBMLSVC_DIR	= $(SRC)/lib/smbsrv/libmlsvc/common
SMBBASE_DIR	= $(SRC)/lib/smbsrv/libsmb/common
SMBCOMMON_DIR	= $(SRC)/common/smbsrv

LIBOBJS =	libshare_smb.o smb_share_doorclnt.o
SMBCOMMON_OBJ =	smb_door_legacy.o
SMBBASE_OBJ =	smb_cfg.o smb_scfutil.o
OBJECTS =	$(LIBOBJS) $(SMBCOMMON_OBJ) $(SMBBASE_OBJ)

include ../../../Makefile.lib

ROOTLIBDIR =	$(ROOT)/usr/lib/fs/smb
ROOTLIBDIR64 =	$(ROOT)/usr/lib/fs/smb/$(MACH64)

LIBSRCS = $(LIBOBJS:%.o=$(SRCDIR)/%.c)
lintcheck := SRCS = $(LIBSRCS)

LIBS =		$(DYNLIB)
LDLIBS +=	-lshare -lscf -luuid -ldlpi -lnsl -lnvpair -lxml2 -lumem -lc

CFLAGS +=	$(CCVERBOSE)
CERRWARN +=	-_gcc=-Wno-char-subscripts
CERRWARN +=	-_gcc=-Wno-switch
CPPFLAGS +=	-D_REENTRANT -I$(ADJUNCT_PROTO)/usr/include/libxml2 \
  		-I$(SRCDIR)/../common
$(ENABLE_SMB_PRINTING) CPPFLAGS += -DHAVE_CUPS

.KEEP_STATE:

all: $(LIBS)

install: all

lint: lintcheck

pics/smb_door_client.o:       $(SMBBASE_DIR)/smb_door_client.c
	$(COMPILE.c) -o $@ $(SMBBASE_DIR)/smb_door_client.c
	$(POST_PROCESS_O)

pics/smb_door_legacy.o:       $(SMBCOMMON_DIR)/smb_door_legacy.c
	$(COMPILE.c) -o $@ $(SMBCOMMON_DIR)/smb_door_legacy.c
	$(POST_PROCESS_O)

pics/smb_cfg.o:       $(SMBBASE_DIR)/smb_cfg.c
	$(COMPILE.c) -o $@ $(SMBBASE_DIR)/smb_cfg.c
	$(POST_PROCESS_O)

pics/smb_scfutil.o:       $(SMBBASE_DIR)/smb_scfutil.c
	$(COMPILE.c) -o $@ $(SMBBASE_DIR)/smb_scfutil.c
	$(POST_PROCESS_O)

include ../../../Makefile.targ
