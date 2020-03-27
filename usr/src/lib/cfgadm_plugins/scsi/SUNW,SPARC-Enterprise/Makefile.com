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

LIBRARY= scsi.a
VERS= .1

GEN_OBJECTS += \
	cfga_ctl.o \
	cfga_cvt.o \
	cfga_list.o \
	cfga_scsi.o \
	cfga_utils.o \
	cfga_rcm.o
OPL_OBJECTS = opl_dev_led.o
OBJECTS += $(GEN_OBJECTS) $(OPL_OBJECTS)

# include library definitions
include $(SRC)/lib/Makefile.lib

ROOTLIBDIR=	$(ROOT)/usr/platform/SUNW,SPARC-Enterprise/lib/cfgadm
ROOTLIBDIR64=	$(ROOTLIBDIR)/$(MACH64)

SRCDIR =	../../common

SRCS=	$(GEN_OBJECTS:%.o=../../common/%.c) $(OPL_OBJECTS:%.o=../common/%.c)

LIBS=	$(DYNLIB)

CFLAGS +=	$(CCVERBOSE)
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	$(CNOWARN_UNINIT)
CERRWARN +=	-_gcc=-Wno-address
CERRWARN +=	-_gcc=-Wno-char-subscripts

LDLIBS +=	-lc -ldevice -ldevinfo -lrcm

.KEEP_STATE:

all:	$(LIBS)


# Install rules

$(ROOTLIBDIR)/%: % $(ROOTLIBDIR)
	$(INS.file)

$(ROOTLIBDIR64)/%: % $(ROOTLIBDIR64)
	$(INS.file)

$(ROOTLIBDIR) $(ROOTLIBDIR64):
	$(INS.dir)

# include library targets
include $(SRC)/lib//Makefile.targ

pics/%.o: ../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
