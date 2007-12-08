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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# psm/stand/boot/sparcv9/Makefile.com


include $(TOPDIR)/psm/stand/boot/Makefile.boot

TARG_MACH	= sparcv9

BOOTSRCDIR	= ../..

TOP_CMN_DIR	= $(SRC)/common
CMN_DIR		= $(BOOTSRCDIR)/common
MACH_DIR	= ../../sparc/common
PLAT_DIR	= .
BOOT_DIR        = $(SRC)/psm/stand/boot

BOOT_SRC	= inetboot.c wanboot.c

CONF_SRC	= nfsconf.c wbfsconf.c wbcli.c

TOP_CMN_C_SRC	= getoptstr.c

MISC_SRC	= ramdisk.c

CMN_C_SRC	= heap_kmem.c readfile.c

MACH_C_SRC	= boot_plat.c bootops.c bootprop.c bootflags.c
MACH_C_SRC	+= get.c

BOOT_OBJS	= $(BOOT_SRC:%.c=%.o)
BOOT_L_OBJS	= $(BOOT_OBJS:%.o=%.ln)

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
CPPINCS		+= -I$(SRC)/common/net/wanboot
CPPINCS		+= -I$(SRC)/common/net/wanboot/crypt
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
# Until we are building on a MACH=sparcv9 machine, we have to override
# where to look for libraries.
#
PSMNAMELIBDIR	= $(PSMSTANDDIR)/lib/names/$(TARG_MACH)
PSMPROMLIBDIR	= $(PSMSTANDDIR)/lib/promif/$(TARG_MACH)

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

#
# Used to convert ELF to an a.out and ensure alignment
#
STRIPALIGN = stripalign

#
# Program used to post-process the ELF executables
#
ELFCONV	= ./$(STRIPALIGN)			# Default value

.KEEP_STATE:

.PARALLEL:	$(OBJS) $(CONF_OBJS) $(MISC_OBJS) $(SRT0_OBJ) $(BOOT_OBJS)
.PARALLEL:	$(L_OBJS) $(CONF_L_OBJS) $(MISC_L_OBJS) $(SRT0_L_OBJ) \
		$(BOOT_L_OBJS)
.PARALLEL:	$(NFSBOOT) $(WANBOOT)

all: $(ELFCONV) $(NFSBOOT) $(WANBOOT)

$(STRIPALIGN): $(CMN_DIR)/$$(@).c
	$(NATIVECC) -o $@ $(CMN_DIR)/$@.c

#
# Note that the presumption is that someone has already done a `make
# install' from usr/src/stand/lib, such that all of the standalone
# libraries have been built and placed in $ROOT/stand/lib.
#
LIBDEPS=	$(LIBPROM_DIR)/libprom.a $(LIBPLAT_DEP) \
		$(LIBNAME_DIR)/libnames.a

L_LIBDEPS=	$(LIBPROM_DIR)/llib-lprom.ln $(LIBPLAT_DEP_L) \
		$(LIBNAME_DIR)/llib-lnames.ln

#
#  WANboot booter
#
# Libraries used to build wanboot
#
# EXPORT DELETE START
LIBWANBOOT =	libwanboot.a
LIBSCRYPT =	libscrypt.a
LIBSSL =	libssl.a
LIBCRYPTO =	libcrypto.a
# EXPORT DELETE END

LIBWAN_LIBS     = \
		$(LIBWANBOOT) \
		libnvpair.a libufs.a libhsfs.a libnfs.a \
		libxdr.a libnames.a libsock.a libinet.a libtcp.a \
		$(LIBSCRYPT) $(LIBSSL) $(LIBCRYPTO) \
		libmd5.a libsa.a libprom.a \
		$(LIBSSL) \
		$(LIBPLAT_LIBS)
WAN_LIBS        = $(LIBWAN_LIBS:lib%.a=-l%)
WAN_DIRS        = $(LIBNAME_DIR:%=-L%) $(LIBSYS_DIR:%=-L%)
WAN_DIRS        += $(LIBPLAT_DIR:%=-L%) $(LIBPROM_DIR:%=-L%)

#
# Loader flags used to build wanboot
#
WAN_MAPFILE	= $(MACH_DIR)/mapfile
WAN_LDFLAGS	= -dn -M $(WAN_MAPFILE) -e _start $(WAN_DIRS)
WAN_L_LDFLAGS	= $(WAN_DIRS)

#
# Object files used to build wanboot
#
WAN_SRT0        = $(SRT0_OBJ)
WAN_OBJS        = $(OBJS) wbfsconf.o wbcli.o wanboot.o ramdisk.o
WAN_L_OBJS      = $(WAN_SRT0:%.o=%.ln) $(WAN_OBJS:%.o=%.ln)

#
# Build rules to build wanboot
#

$(WANBOOT).elf: $(WAN_MAPFILE) $(WAN_SRT0) $(WAN_OBJS) $(LIBDEPS)
	$(LD) $(WAN_LDFLAGS) -o $@ $(WAN_SRT0) $(WAN_OBJS) $(WAN_LIBS)
	$(MCS) -d $@
	$(POST_PROCESS)
	$(POST_PROCESS)
	$(MCS) -c $@

$(WANBOOT): $(WANBOOT).elf
	$(RM) $@; cp $@.elf $@
	$(STRIP) $@

$(WANBOOT)_lint: $(L_LIBDEPS) $(WAN_L_OBJS)
	@echo ""
	@echo wanboot lint: global crosschecks:
	$(LINT.c) $(WAN_L_LDFLAGS) $(WAN_L_OBJS) $(WAN_LIBS)

# High-sierra filesystem booter.  Probably doesn't work.

# NFS booter

#
# Libraries used to build nfsboot
#
LIBNFS_LIBS     = libnfs.a libxdr.a libnames.a \
		libsock.a libinet.a libtcp.a libsa.a libprom.a \
		$(LIBPLAT_LIBS)
NFS_LIBS        = $(LIBNFS_LIBS:lib%.a=-l%)
NFS_DIRS        = $(LIBNAME_DIR:%=-L%) $(LIBSYS_DIR:%=-L%)
NFS_DIRS        += $(LIBPLAT_DIR:%=-L%) $(LIBPROM_DIR:%=-L%)

#
# Loader flags used to build inetboot
#
NFS_MAPFILE	= $(MACH_DIR)/mapfile
NFS_LDFLAGS	= -dn -M $(NFS_MAPFILE) -e _start $(NFS_DIRS)
NFS_L_LDFLAGS	= $(NFS_DIRS)

#
# Object files used to build inetboot
#
NFS_SRT0        = $(SRT0_OBJ)
NFS_OBJS        = $(OBJS) nfsconf.o inetboot.o ramdisk.o
NFS_L_OBJS      = $(NFS_SRT0:%.o=%.ln) $(NFS_OBJS:%.o=%.ln)

$(NFSBOOT).elf: $(ELFCONV) $(NFS_MAPFILE) $(NFS_SRT0) $(NFS_OBJS) $(LIBDEPS)
	$(LD) $(NFS_LDFLAGS) -o $@ $(NFS_SRT0) $(NFS_OBJS) $(NFS_LIBS)
	$(MCS) -d $@
	$(POST_PROCESS)
	$(POST_PROCESS)
	$(MCS) -c $@

#
# This is a bit strange because some platforms boot elf and some don't.
# So this rule strips the file no matter which ELFCONV is used.
#
$(NFSBOOT): $(NFSBOOT).elf
	$(RM) $@.tmp; cp $@.elf $@.tmp; $(STRIP) $@.tmp
	$(RM) $@; $(ELFCONV) $@.tmp $@; $(RM) $@.tmp

$(NFSBOOT)_lint: $(NFS_L_OBJS) $(L_LIBDEPS)
	@echo ""
	@echo inetboot lint: global crosschecks:
	$(LINT.c) $(NFS_L_LDFLAGS) $(NFS_L_OBJS) $(NFS_LIBS)

include $(BOOTSRCDIR)/Makefile.rules

install: $(ROOT_PSM_WANBOOT)

clean:
	$(RM) make.out lint.out
	$(RM) $(OBJS) $(CONF_OBJS) $(MISC_OBJS) $(BOOT_OBJS) $(SRT0_OBJ)
	$(RM) $(NFSBOOT).elf $(WANBOOT).elf
	$(RM) $(L_OBJS) $(CONF_L_OBJS) $(MISC_L_OBJS) $(BOOT_L_OBJS) \
	      $(SRT0_L_OBJ)

clobber: clean
	$(RM) $(NFSBOOT) $(WANBOOT) $(STRIPALIGN)

lint: $(NFSBOOT)_lint $(WANBOOT)_lint

include $(BOOTSRCDIR)/Makefile.targ
