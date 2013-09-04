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

LIBRARY= sbd.a
VERS= .1

OBJECTS= ap.o ap_msg.o ap_rcm.o ap_sbd.o ap_seq.o cfga.o ap_err.o

# include library definitions
include ../../../Makefile.lib

USR_PLAT_DIR		= $(ROOT)/usr/platform
USR_PSM_DIR		= $(USR_PLAT_DIR)/$(PLATFORM)
USR_PSM_LIB_DIR		= $(USR_PSM_DIR)/lib
USR_PSM_LIB_CFG_DIR	= $(USR_PSM_LIB_DIR)/cfgadm
USR_PSM_LIB_CFG_DIR_64	= $(USR_PSM_LIB_CFG_DIR)/$(MACH64)

ROOTLIBDIR=     $(USR_PSM_LIB_CFG_DIR)
ROOTLIBDIR64=   $(USR_PSM_LIB_CFG_DIR_64)

SRCDIR =	../common

LIBS = $(DYNLIB)

CFLAGS +=	$(CCVERBOSE)
LDLIBS +=	-lc -lkstat -lnvpair

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-char-subscripts
CERRWARN +=	-_gcc=-Wno-uninitialized

CPPFLAGS +=	-I$(ROOT)/usr/platform/$(PLATFORM)/include -DSBD_DEBUG
#
#	Generate the error messages form sbd_ioctl.h
#
GENERRDIR=	$(SRC)/lib/cfgadm_plugins/sbd
GENERR=		$(GENERRDIR)/sbdgenerr
ERRSRC=		$(ROOT)/usr/platform/$(PLATFORM)/include/sys/sbd_ioctl.h

.KEEP_STATE:

all: $(LIBS)

lint:   lintcheck

# Create target directories
$(USR_PSM_DIR):
	-$(INS.dir)

$(USR_PSM_LIB_DIR):	$(USR_PSM_DIR)
	-$(INS.dir)

$(USR_PSM_LIB_CFG_DIR):	$(USR_PSM_LIB_DIR)
	-$(INS.dir)

$(USR_PSM_LIB_CFG_DIR_64):	$(USR_PSM_LIB_CFG_DIR)
	-$(INS.dir)

$(USR_PSM_LIB_CFG_DIR)/%: % $(USR_PSM_LIB_CFG_DIR)
	-$(INS.file)

$(USR_PSM_LIB_CFG_DIR_64)/%: % $(USR_PSM_LIB_CFG_DIR_64)
	-$(INS.file)

CLOBBERFILES += ../common/ap_err.c sbdgenerr $(GENERR)

# include library targets
include ../../../Makefile.targ

pics/%.o: ../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

../common/ap_err.c: sbdgenerr $(ERRSRC)
	$(GENERRDIR)/sbdgenerr < $(ERRSRC) > ../common/ap_err.c

sbdgenerr: $(GENERRDIR)/sbdgenerr.pl
	$(RM) $(GENERRDIR)/sbdgenerr 
	cat $(GENERRDIR)/sbdgenerr.pl > $(GENERRDIR)/sbdgenerr
	$(CHMOD) +x $(GENERRDIR)/sbdgenerr
