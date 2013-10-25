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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# uts/sun4u/sys/Makefile
#
UTSBASE	= ../..

#
# include global definitions
#
include ../Makefile.sun4u

#
# Override defaults.
#
FILEMODE	 = 644

SUN4_HDRS=			\
	async.h			\
	clock.h			\
	cmp.h			\
	cpc_ultra.h		\
	cpu_sgnblk_defs.h 	\
	ddi_subrdefs.h		\
	dvma.h			\
	eeprom.h		\
	errclassify.h		\
	fcode.h			\
	fc_plat.h		\
	idprom.h		\
	intr.h			\
	intreg.h		\
	ivintr.h		\
	memlist_plat.h  	\
	memnode.h		\
	nexusdebug.h		\
	prom_debug.h		\
	scb.h			\
	sun4asi.h		\
	tod.h			\
	trapstat.h		\
	vis.h			\
	vm_machparam.h		\
	x_call.h		\
	xc_impl.h		\
	zsmach.h

HDRS=	\
	cheetahregs.h		\
	cpr_impl.h		\
	cpu_impl.h		\
	ecc_kstat.h		\
	envctrl.h		\
	envctrl_gen.h		\
	envctrl_ue250.h		\
	envctrl_ue450.h		\
	gpio_87317.h		\
	iocache.h		\
	iommu.h			\
	machasi.h		\
	machclock.h		\
	machcpuvar.h		\
	machparam.h		\
	machsystm.h		\
	machthread.h		\
	mem_cache.h		\
	mmu.h			\
	opl_module.h		\
	prom_plat.h		\
	pte.h			\
	sbd_ioctl.h		\
	spitregs.h		\
	starfire.h		\
	sysioerr.h		\
	sysiosbus.h		\
	todmostek.h		\
	traptrace.h

I2CHDRS =	clients/max1617.h misc/i2c_svc.h clients/i2c_client.h	\
		clients/hpc3130.h clients/lm75.h	\
		clients/pcf8591.h clients/ssc050.h

I2C_DIRS=	clients misc
USR_PSM_ISYS_I2C_ROOT=	$(USR_PSM_ISYS_DIR)/i2c
USR_PSM_ISYS_I2C_DIRS=	$(USR_PSM_ISYS_I2C_ROOT) \
			$(I2C_DIRS:%=$(USR_PSM_ISYS_I2C_ROOT)/%)

ROOTI2CHDRS=		$(I2CHDRS:%=$(USR_PSM_ISYS_I2C_ROOT)/%)

MONHDRS=
#MONHDRS=	eeprom.h    idprom.h    keyboard.h  password.h

USR_PSM_MON_DIR=	$(USR_PSM_ISYS_DIR)/mon

ROOTHDRS=		$(HDRS:%=$(USR_PSM_ISYS_DIR)/%)

SUN4_ROOTHDRS=		$(SUN4_HDRS:%=$(USR_PSM_ISYS_DIR)/%)

ROOTMONHDRS=		$(MONHDRS:%=$(USR_PSM_MON_DIR)/%)

ROOTDIR=		$(ROOT)/usr/share/src
ROOTDIRS=		$(ROOTDIR)/uts $(ROOTDIR)/uts/$(PLATFORM)

ROOTLINK=		$(ROOTDIR)/uts/$(PLATFORM)/sys
LINKDEST=		../../../../platform/$(PLATFORM)/include/sys

CHECKHDRS=		$(HDRS:%.h=%.check) \
			$(MONHDRS:%.h=mon/%.check) \
			$(SUN4_HDRS:%.h=%.cmncheck)

.KEEP_STATE:

.PARALLEL: $(CHECKHDRS) $(ROOTHDRS) $(ROOTMONHDRS) $(SUN4_ROOTHDRS)

install_h: $(ROOTDIRS) $(USR_PSM_ISYS_I2C_DIRS) .WAIT \
		$(ROOTHDRS) $(ROOTI2CHDRS) \
		$(ROOTMONHDRS) \
		$(SUN4_ROOTHDRS) $(ROOTLINK)

check:	$(CHECKHDRS)

#
# install rules
#
$(USR_PSM_MON_DIR):	$(USR_PSM_ISYS_DIR)
	$(INS.dir)

$(USR_PSM_ISYS_I2C_DIRS):
	$(INS.dir)

$(USR_PSM_ISYS_DIR)/%:	../../sfmmu/sys/% $(USR_PSM_ISYS_DIR)
	$(INS.file)

$(USR_PSM_ISYS_DIR)/%:	../../sun4/sys/% $(USR_PSM_ISYS_DIR)
	$(INS.file)

$(USR_PSM_MON_DIR)/%:	mon/% $(USR_PSM_MON_DIR)
	$(INS.file)

$(ROOTDIRS):
	$(INS.dir)

# -r because this used to be a directory and is now a link.
$(ROOTLINK):	$(ROOTDIRS)
	-$(RM) -r $@; $(SYMLINK) $(LINKDEST) $@

mon/%.check:	mon/%.h
	$(DOT_H_CHECK)

%.check:	../../sfmmu/sys/%.h
	$(DOT_H_CHECK)
%.cmncheck:	../../sun4/sys/%.h
	$(DOT_H_CHECK)

FRC:

include ../../Makefile.targ
