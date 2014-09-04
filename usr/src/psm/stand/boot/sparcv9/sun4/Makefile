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
# Copyright 2014 Gary Mills
#
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

TOPDIR =	../../../../..

include $(TOPDIR)/uts/Makefile.uts

all	:=	TARGET = all
install	:=	TARGET = install
clean	:=	TARGET = clean

TARG_MACH =	sparcv9
TARG_MACH_DIR =	sparcv9
ARCHVERS =	v9
PLATFORM =	sun4
#ARCHMMU  =	sfmmu
PROMVERS =	ieee1275
ASFLAGS +=	$(sparcv9_XARCH)

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

include ../Makefile.com

CPPINCS		+= -I$(TOPDIR)/psm/stand/boot/sparc/sun4

#
# Set the choice of compiler. 

include $(TOPDIR)/psm/Makefile.psm.64

CFLAGS64	+= -xchip=ultra $(CCABS32)

#
# XXX this totally sucks since it effectively turns off -errchk=longptr64,
# which we really should be using.
#
LINTFLAGS64 = $(LINTFLAGS) -m64

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


#############################
#
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


#include $(BOOTSRCDIR)/Makefile.rules

FRC:

.KEEP_STATE:

all: $(NFSBOOT)

install: all					\
	$(USR_PLAT_SUN4U_LIB_FS_NFS_NFSBOOT)	\
	$(USR_PLAT_SUN4V_LIB_FS_NFS_NFSBOOT)

$(NFSBOOT): $(NFS_MAPFILE) $(NFS_SRT0) $(NFS_OBJS) $(LIBDEPS)
	$(LD) $(NFS_LDFLAGS) -o $@ $(NFS_SRT0) $(NFS_OBJS) $(NFS_LIBS)
	$(MCS) -d $@
	$(POST_PROCESS)
	$(MCS) -c $@
	$(STRIP) $@

$(NFSBOOT)_lint: $(NFS_L_OBJS) $(L_LIBDEPS)
	@echo ""
	@echo inetboot lint: global crosschecks:
	$(LINT.c) $(NFS_L_LDFLAGS) $(NFS_L_OBJS) $(NFS_LIBS)

$(USR_PLAT_SUN4U_LIB_FS_NFS):
	$(INS.dir)

$(USR_PLAT_SUN4V_LIB_FS_NFS):
	$(INS.dir)

$(USR_PLAT_SUN4U_LIB_FS_NFS_NFSBOOT): $(USR_PLAT_SUN4U_LIB_FS_NFS) $(NFSBOOT)
	$(INS) -s -m $(FILEMODE) -f $(USR_PLAT_SUN4U_LIB_FS_NFS) $(NFSBOOT)

$(USR_PLAT_SUN4V_LIB_FS_NFS_NFSBOOT): $(USR_PLAT_SUN4V_LIB_FS_NFS) $(NFSBOOT)
	$(INS) -s -m $(FILEMODE) -f $(USR_PLAT_SUN4V_LIB_FS_NFS) $(NFSBOOT)

$(STRIPALIGN): $(CMN_DIR)/$$(@).c
	$(NATIVECC) -o $@ $(CMN_DIR)/$@.c

clean:
	$(RM) make.out lint.out
	$(RM) $(OBJS) $(CONF_OBJS) $(MISC_OBJS) $(SRT0_OBJ)
	$(RM) $(NFSBOOT_OBJS)
	$(RM) $(L_OBJS) $(CONF_L_OBJS) $(MISC_L_OBJS) $(SRT0_L_OBJ)
	$(RM) $(NFSBOOT_L_OBJS)

clobber: clean
	$(RM) $(NFSBOOT) $(STRIPALIGN)

lint: $(NFSBOOT)_lint
