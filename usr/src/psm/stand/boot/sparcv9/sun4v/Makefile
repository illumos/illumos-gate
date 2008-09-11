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

PLAT_C_SRC =	machdep.c
ARCH_C_SRC =	sun4u_memlist.c sun4x_standalloc.c sun4dep.c
ARCH_S_SRC =	sparcv9_subr.s
SRT0_S =	sun4u_srt0.s
INLINES =

LDFLAGS +=	-L$(TOPDIR)/psm/stand/lib/promif/$(TARG_MACH)/$(PROMVERS)/common

#
# The following libraries are build in LIBPLAT_DIR
#
LIBPLAT_DIR =	$(TOPDIR)/psm/stand/lib/promif/$(TARG_MACH)/$(PROMVERS)/$(PLATFORM)
LIBPLAT_LIBS =  libplat.a
LIBPLAT_L_LIBS=	$(LIBPLAT_LIBS:lib%.a=llib-l%.ln)
LIBPLAT_DEP = 	$(LIBPLAT_DIR)/$(LIBPLAT_LIBS)
LIBPLAT_DEP_L =	$(LIBPLAT_DIR)/$(LIBPLAT_L_LIBS)

#
# Platform specific libraries
#
PSMLIBS +=      $(LIBPLAT_LIBS:lib%.a=-l%)
PSMLIB_DIRS +=  $(LIBPLAT_DIR)


#	MPSAS support
MPSAS_BUILD:sh=		echo \\043
$(MPSAS_BUILD)ARCHOPTS += -DMPSAS

include ../Makefile.com

CPPINCS		+= -I$(SRC)/uts/sun4u
CPPINCS		+= -I$(ROOT)/usr/platform/sun4u/include

# re-define ELFCONV for 4v--- sun4v can boot ELF directly
ELFCONV = /usr/bin/cp

# Don't need mapfile.inet for 4v inetboot
NFS_MAPFILE = $(MACH_DIR)/mapfile

#
# Set the choice of compiler. 

include $(TOPDIR)/psm/Makefile.psm.64

CFLAGS64	+= -xchip=ultra $(CCABS32)

#
# XXX this totally sucks since it effectively turns off -errchk=longptr64,
# which we really should be using.
#
LINTFLAGS64 = $(LINTFLAGS) -Xarch=v9

#
# Cross-reference customization: include all boot-related source files.
#
STANDLIBDIR=	../../../../../stand/lib
STANDSYSDIR=	../../../../../stand/sys
PROMDIRS=	../../../../promif
NAMESDIRS=	../../../lib/names/sparcv9 ../../../lib/names/sparc/common
XRDIRS +=	../../sparc/common ../../common $(STANDLIBDIR) \
		$(STANDSYSDIR) $(PROMDIRS) $(NAMESDIRS)
XRPRUNE =	i86pc i386

cscope.out tags: FRC
	$(XREF) -x $@

FRC:
