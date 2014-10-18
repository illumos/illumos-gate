#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
#

LIBMDIR		= $(SRC)/lib/libm

mvecOBJS	= \
		__vTBL_atan1.o \
		__vTBL_atan2.o \
		__vTBL_rsqrt.o \
		__vTBL_sincos.o \
		__vTBL_sincos2.o \
		__vTBL_sqrtf.o \
		__vatan.o \
		__vatan2.o \
		__vatan2f.o \
		__vatanf.o \
		__vc_abs.o \
		__vc_exp.o \
		__vc_log.o \
		__vc_pow.o \
		__vcos.o \
		__vcosbig.o \
		__vcosbigf.o \
		__vcosf.o \
		__vexp.o \
		__vexpf.o \
		__vhypot.o \
		__vhypotf.o \
		__vlog.o \
		__vlogf.o \
		__vpow.o \
		__vpowf.o \
		__vrem_pio2m.o \
		__vrhypot.o \
		__vrhypotf.o \
		__vrsqrt.o \
		__vrsqrtf.o \
		__vsin.o \
		__vsinbig.o \
		__vsinbigf.o \
		__vsincos.o \
		__vsincosbig.o \
		__vsincosbigf.o \
		__vsincosf.o \
		__vsinf.o \
		__vsqrt.o \
		__vsqrtf.o \
		__vz_abs.o \
		__vz_exp.o \
		__vz_log.o \
		__vz_pow.o \
		vatan2_.o \
		vatan2f_.o \
		vatan_.o \
		vatanf_.o \
		vc_abs_.o \
		vc_exp_.o \
		vc_log_.o \
		vc_pow_.o \
		vcos_.o \
		vcosf_.o \
		vexp_.o \
		vexpf_.o \
		vhypot_.o \
		vhypotf_.o \
		vlog_.o \
		vlogf_.o \
		vpow_.o \
		vpowf_.o \
		vrhypot_.o \
		vrhypotf_.o \
		vrsqrt_.o \
		vrsqrtf_.o \
		vsin_.o \
		vsincos_.o \
		vsincosf_.o \
		vsinf_.o \
		vsqrt_.o \
		vsqrtf_.o \
		vz_abs_.o \
		vz_exp_.o \
		vz_log_.o \
		vz_pow_.o \
		#end

mvecvisCOBJS	= \
		__vTBL_atan1.o \
		__vTBL_atan2.o \
		__vTBL_rsqrt.o \
		__vTBL_sincos.o \
		__vTBL_sincos2.o \
		__vTBL_sqrtf.o \
		__vcosbig.o \
		__vcosbigf.o \
		__vrem_pio2m.o \
		__vsinbig.o \
		__vsinbigf.o \
		__vsincosbig.o \
		__vsincosbigf.o \
		#end

mvecvisSOBJS	= \
		__vatan.o \
		__vatan2.o \
		__vatan2f.o \
		__vatanf.o \
		__vcos.o \
		__vcosf.o \
		__vexp.o \
		__vexpf.o \
		__vhypot.o \
		__vhypotf.o \
		__vlog.o \
		__vlogf.o \
		__vpow.o \
		__vpowf.o \
		__vrhypot.o \
		__vrhypotf.o \
		__vrsqrt.o \
		__vrsqrtf.o \
		__vsin.o \
		__vsincos.o \
		__vsincosf.o \
		__vsinf.o \
		__vsqrt.o \
		__vsqrtf.o \
		#end

mvecvis2COBJS	= \
		__vTBL_sincos.o \
		__vTBL_sincos2.o \
		__vTBL_sqrtf.o \
		__vcosbig.o \
		__vcosbig_ultra3.o \
		__vrem_pio2m.o \
		__vsinbig.o \
		__vsinbig_ultra3.o \
		#end

mvecvis2SOBJS	= \
		__vcos_ultra3.o \
		__vlog_ultra3.o \
		__vsin_ultra3.o \
		__vsqrtf_ultra3.o \
		#end

include		$(SRC)/lib/Makefile.lib
include		$(SRC)/lib/Makefile.rootfs
include		$(LIBMDIR)/Makefile.libm.com

LIBS		= $(DYNLIB)
SRCDIR		= ../common/
DYNFLAGS	+= -zignore

LINTERROFF	= -erroff=E_FP_DIVISION_BY_ZERO 
LINTERROFF	+= -erroff=E_FP_INVALID
LINTERROFF	+= -erroff=E_BAD_PTR_CAST_ALIGN
LINTERROFF	+= -erroff=E_ASSIGMENT_CAUSE_LOSS_PREC
LINTERROFF	+= -erroff=E_FUNC_SET_NOT_USED

LINTFLAGS	+= $(LINTERROFF)
LINTFLAGS64	+= $(LINTERROFF)
LINTFLAGS64     += -errchk=longptr64

CLAGS		+= $(LINTERROFF)
CFLAGS64	+= $(LINTERROFF)

ASDEF		+= -DLIBMVEC_SO_BUILD

FLTRPATH_sparc		= $$ORIGIN/cpu/$$ISALIST/libmvec_isa.so.1
FLTRPATH_sparcv9	= $$ORIGIN/../cpu/$$ISALIST/sparcv9/libmvec_isa.so.1
FLTRPATH_i386		= $$ORIGIN/libmvec/$$HWCAP
FLTRPATH		= $(FLTRPATH_$(TARGET_ARCH))

sparc_CFLAGS += -_cc=-W0,-xintrinsic
sparcv9_CFLAGS += -_cc=-W0,-xintrinsic
CPPFLAGS_i386	+= -Dfabs=__fabs

CPPFLAGS	+= -DLIBMVEC_SO_BUILD

SRCS_mvec_i386 = \
	../common/__vsqrtf.c \
	#end

SRCS_mvec_sparc = \
	$(SRCS_mvec_i386) \
	#end
SRCS_mvec_sparcv9 = \
	$(SRCS_mvec_i386) \
	#end

SRCS_mvec = \
	$(SRCS_mvec_$(TARGETMACH)) \
	../common/__vTBL_atan1.c \
	../common/__vTBL_atan2.c \
	../common/__vTBL_rsqrt.c \
	../common/__vTBL_sincos.c \
	../common/__vTBL_sincos2.c \
	../common/__vTBL_sqrtf.c \
	../common/__vatan.c \
	../common/__vatan2.c \
	../common/__vatan2f.c \
	../common/__vatanf.c \
	../common/__vc_abs.c \
	../common/__vc_exp.c \
	../common/__vc_log.c \
	../common/__vc_pow.c \
	../common/__vcos.c \
	../common/__vcosbig.c \
	../common/__vcosbigf.c \
	../common/__vcosf.c \
	../common/__vexp.c \
	../common/__vexpf.c \
	../common/__vhypot.c \
	../common/__vhypotf.c \
	../common/__vlog.c \
	../common/__vlogf.c \
	../common/__vpow.c \
	../common/__vpowf.c \
	../common/__vrem_pio2m.c \
	../common/__vrhypot.c \
	../common/__vrhypotf.c \
	../common/__vrsqrt.c \
	../common/__vrsqrtf.c \
	../common/__vsin.c \
	../common/__vsinbig.c \
	../common/__vsinbigf.c \
	../common/__vsincos.c \
	../common/__vsincosbig.c \
	../common/__vsincosbigf.c \
	../common/__vsincosf.c \
	../common/__vsinf.c \
	../common/__vsqrt.c \
	../common/__vz_abs.c \
	../common/__vz_exp.c \
	../common/__vz_log.c \
	../common/__vz_pow.c \
	../common/vatan2_.c \
	../common/vatan2f_.c \
	../common/vatan_.c \
	../common/vatanf_.c \
	../common/vc_abs_.c \
	../common/vc_exp_.c \
	../common/vc_log_.c \
	../common/vc_pow_.c \
	../common/vcos_.c \
	../common/vcosf_.c \
	../common/vexp_.c \
	../common/vexpf_.c \
	../common/vhypot_.c \
	../common/vhypotf_.c \
	../common/vlog_.c \
	../common/vlogf_.c \
	../common/vpow_.c \
	../common/vpowf_.c \
	../common/vrhypot_.c \
	../common/vrhypotf_.c \
	../common/vrsqrt_.c \
	../common/vrsqrtf_.c \
	../common/vsin_.c \
	../common/vsincos_.c \
	../common/vsincosf_.c \
	../common/vsinf_.c \
	../common/vsqrt_.c \
	../common/vsqrtf_.c \
	../common/vz_abs_.c \
	../common/vz_exp_.c \
	../common/vz_log_.c \
	../common/vz_pow_.c \
	#end

.KEEP_STATE:

all:	$(LIBS)

lint:	lintcheck

pics/%.o: ../$(TARGET_ARCH)/src/%.S
	$(COMPILE.s) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../common/$$(CHIP)/%.S
	$(COMPILE.s) -o $@ $<
	$(POST_PROCESS_O)
