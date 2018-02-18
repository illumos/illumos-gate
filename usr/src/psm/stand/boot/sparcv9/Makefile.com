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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# psm/stand/boot/sparcv9/Makefile.com


include $(TOPDIR)/psm/stand/boot/Makefile.boot

TARG_MACH	= sparcv9

BOOTSRCDIR	= ../..

TOP_CMN_DIR	= $(SRC)/common
CMN_DIR		= $(BOOTSRCDIR)/common
MACH_DIR	= ../../sparc/common
PLAT_DIR	= sun4
BOOT_DIR        = $(SRC)/psm/stand/boot

NFSBOOT		= inetboot

NFSBOOT_SRC	= $(NFSBOOT).c

CONF_SRC	= nfsconf.c

TOP_CMN_C_SRC	= getoptstr.c

MISC_SRC	= ramdisk.c

CMN_C_SRC	= heap_kmem.c readfile.c

MACH_C_SRC	= boot_plat.c bootops.c bootprop.c bootflags.c
MACH_C_SRC	+= machdep.c sun4u_machdep.c sun4v_machdep.c
MACH_C_SRC	+= get.c

NFSBOOT_OBJS	= $(NFSBOOT_SRC:%.c=%.o)
NFSBOOT_L_OBJS	= $(NFSBOOT_OBJS:%.o=%.ln)

CONF_OBJS	= $(CONF_SRC:%.c=%.o)
CONF_L_OBJS	= $(CONF_OBJS:%.o=%.ln)

MISC_OBJS	= $(MISC_SRC:%.c=%.o)
MISC_L_OBJS	= $(MISC_OBJS:%.o=%.ln)

SRT0_OBJ	= $(SRT0_S:%.s=%.o)
SRT0_L_OBJ	= $(SRT0_OBJ:%.o=%.ln)

C_SRC		= $(TOP_CMN_C_SRC) $(CMN_C_SRC) $(MACH_C_SRC) $(ARCH_C_SRC)
C_SRC		+= $(PLAT_C_SRC)
S_SRC		= $(MACH_S_SRC) $(ARCH_S_SRC) $(PLAT_S_SRC)

OBJS		= $(C_SRC:%.c=%.o) $(S_SRC:%.s=%.o)
L_OBJS		= $(OBJS:%.o=%.ln)

CPPDEFS		= $(ARCHOPTS) -D$(PLATFORM) -D_BOOT -D_KERNEL -D_MACHDEP
CPPDEFS		+= -D_ELF64_SUPPORT
CPPINCS		+= -I$(TOP_CMN_DIR)
CPPINCS		+= -I$(SRC)/uts/common
CPPINCS		+= -I$(SRC)/uts/sun
CPPINCS		+= -I$(SRC)/uts/sun4
CPPINCS		+= -I$(SRC)/uts/$(PLATFORM)
CPPINCS		+= -I$(SRC)/uts/sparc/$(ARCHVERS)
CPPINCS		+= -I$(SRC)/uts/sparc
CPPINCS		+= -I$(SRC)/uts/$(ARCHMMU)
CPPINCS		+= -I$(ROOT)/usr/platform/$(PLATFORM)/include
CPPINCS		+= -I$(ROOT)/usr/include/$(ARCHVERS)
CPPINCS		+= -I$(PSMSYSHDRDIR)
CPPINCS		+= -I$(STANDDIR)
CPPINCS		+= -I$(STANDDIR)/lib
CPPINCS		+= -I$(STANDDIR)/lib/sa
CPPINCS		+= -I$(SRC)/common/net/dhcp
CPPINCS		+= -I$(BOOT_DIR)/sparc/common
CPPFLAGS	= $(CPPDEFS) $(CPPINCS)
CPPFLAGS	+= $(CCYFLAG)$(STANDDIR)
ASFLAGS		+= $(CPPDEFS) -P -D_ASM $(CPPINCS)
CFLAGS64	+= ../../sparc/common/sparc.il

#
# Where to look for libraries.
#
PSMNAMELIBDIR	= $(PSMSTANDDIR)/lib/names/$(TARG_MACH)
PSMPROMLIBDIR	= $(PSMSTANDDIR)/lib/promif/$(TARG_MACH)

#
# Install targets
#
USR_PLAT_SUN4U_LIB=$(USR_PLAT_DIR)/sun4u/lib
USR_PLAT_SUN4U_LIB_FS=$(USR_PLAT_SUN4U_LIB)/fs
USR_PLAT_SUN4U_LIB_FS_NFS=$(USR_PLAT_SUN4U_LIB_FS)/nfs
USR_PLAT_SUN4U_LIB_FS_NFS_NFSBOOT=$(USR_PLAT_SUN4U_LIB_FS_NFS)/$(NFSBOOT)

USR_PLAT_SUN4V_LIB=$(USR_PLAT_DIR)/sun4v/lib
USR_PLAT_SUN4V_LIB_FS=$(USR_PLAT_SUN4V_LIB)/fs
USR_PLAT_SUN4V_LIB_FS_NFS=$(USR_PLAT_SUN4V_LIB_FS)/nfs
USR_PLAT_SUN4V_LIB_FS_NFS_NFSBOOT=$(USR_PLAT_SUN4V_LIB_FS_NFS)/$(NFSBOOT)

#
# The following libraries are built in LIBNAME_DIR
#
LIBNAME_DIR     += $(PSMNAMELIBDIR)/$(PLATFORM)
LIBNAME_LIBS    += libnames.a

#
# The following libraries are built in LIBPROM_DIR
#
LIBPROM_DIR     += $(PSMPROMLIBDIR)/$(PROMVERS)/common
LIBPROM_LIBS    += libprom.a

#
# The following libraries are built in LIBSYS_DIR
#
LIBSYS_DIR      += $(SYSLIBDIR)

#.KEEP_STATE:
#

.PARALLEL:	$(OBJS) $(CONF_OBJS) $(MISC_OBJS) $(SRT0_OBJ) \
		$(NFSBOOT_OBJS)
.PARALLEL:	$(L_OBJS) $(CONF_L_OBJS) $(MISC_L_OBJS) $(SRT0_L_OBJ) \
		$(NFSBOOT_L_OBJS)
.PARALLEL:	$(NFSBOOT)

#
# Note that the presumption is that someone has already done a `make
# install' from usr/src/stand/lib, such that all of the standalone
# libraries have been built and placed in $ROOT/stand/lib.
#
LIBDEPS=	$(LIBPROM_DIR)/libprom.a $(LIBPLAT_DEP) \
		$(LIBNAME_DIR)/libnames.a

L_LIBDEPS=	$(LIBPROM_DIR)/llib-lprom.ln $(LIBPLAT_DEP_L) \
		$(LIBNAME_DIR)/llib-lnames.ln

include $(BOOTSRCDIR)/Makefile.rules
include $(BOOTSRCDIR)/Makefile.targ
