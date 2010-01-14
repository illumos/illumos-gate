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

TOPDIR =	../../../../..

include $(TOPDIR)/uts/Makefile.uts

MODULE	= fs

PLATLINKS	= SUNW,Sun-Fire-T200
PLATLINKS	+= SUNW,Netra-CP3060
PLATLINKS	+= SUNW,Netra-CP3260
PLATLINKS	+= SUNW,Sun-Blade-T6300
PLATLINKS	+= SUNW,Sun-Blade-T6320
PLATLINKS	+= SUNW,SPARC-Enterprise-T5120
PLATLINKS	+= SUNW,T5140
PLATLINKS	+= SUNW,USBRDT-5240
PLATLINKS	+= SUNW,Netra-T5220
PLATLINKS	+= SUNW,Netra-T5440

LINKED_DIRS	= $(PLATLINKS:%=$(USR_PLAT_DIR)/%)
LINKED_LIB_DIRS	= $(PLATLINKS:%=$(USR_PLAT_DIR)/%/lib)
LINKED_LIB_FS_DIRS	= $(PLATLINKS:%=$(USR_PLAT_DIR)/%/lib/fs)

all	:=	TARGET = all
install	:=	TARGET = install
clean	:=	TARGET = clean

TARG_MACH =	sparcv9
TARG_MACH_DIR =	sparcv9
ARCHVERS =	v9
PLATFORM =	sun4v
ARCHMMU  =	sfmmu
PROMVERS =	ieee1275
ASFLAGS +=	$(sparcv9_XARCH)

include ../Makefile.com
include $(TOPDIR)/psm/Makefile.psm.64
include $(BOOTSRCDIR)/Makefile.rules

FRC:

.KEEP_STATE:

all:

install: all $(LINKED_DIRS) $(LINKED_LIB_DIRS) $(LINKED_LIB_FS_DIRS)

clean:

clobber: clean

lint:

FRC:
