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

LIBRARY		= libm.a
VERS		= .2

LIBMDIR		= $(SRC)/lib/libm

m9xsseOBJS_i386	= \
		__fex_hdlr.o \
		__fex_i386.o \
		__fex_sse.o \
		__fex_sym.o \
		fex_log.o

m9xsseOBJS	= $(m9xsseOBJS_$(TARGET_ARCH))

m9xOBJS_amd64	= \
		__fex_sse.o \
		feprec.o

m9xOBJS_sparc	= \
		lrint.o \
		lrintf.o \
		lrintl.o \
		lround.o \
		lroundf.o \
		lroundl.o

m9xOBJS_i386	= \
		__fex_sse.o \
		feprec.o \
		lrint.o \
		lrintf.o \
		lrintl.o \
		lround.o \
		lroundf.o \
		lroundl.o

#
# lrint.o, lrintf.o, lrintl.o, lround.o, lroundf.o & lroundl.o are 32-bit only
#
m9xOBJS		= \
		$(m9xOBJS_$(TARGET_ARCH)) \
		__fex_$(MACH).o \
		__fex_hdlr.o \
		__fex_sym.o \
		fdim.o \
		fdimf.o \
		fdiml.o \
		feexcept.o \
		fenv.o \
		feround.o \
		fex_handler.o \
		fex_log.o \
		fma.o \
		fmaf.o \
		fmal.o \
		fmax.o \
		fmaxf.o \
		fmaxl.o \
		fmin.o \
		fminf.o \
		fminl.o \
		frexp.o \
		frexpf.o \
		frexpl.o \
		ldexp.o \
		ldexpf.o \
		ldexpl.o \
		llrint.o \
		llrintf.o \
		llrintl.o \
		llround.o \
		llroundf.o \
		llroundl.o \
		modf.o \
		modff.o \
		modfl.o \
		nan.o \
		nanf.o \
		nanl.o \
		nearbyint.o \
		nearbyintf.o \
		nearbyintl.o \
		nexttoward.o \
		nexttowardf.o \
		nexttowardl.o \
		remquo.o \
		remquof.o \
		remquol.o \
		round.o \
		roundf.o \
		roundl.o \
		scalbln.o \
		scalblnf.o \
		scalblnl.o \
		tgamma.o \
		tgammaf.o \
		tgammal.o \
		trunc.o \
		truncf.o \
		truncl.o

OBJS_M9XSSE	= $(m9xsseOBJS:%=pics/%)

COBJS_i386	= \
		__libx_errno.o

COBJS_sparc	= \
		$(COBJS_i386) \
		_TBL_atan.o \
		_TBL_exp2.o \
		_TBL_log.o \
		_TBL_log2.o \
		_TBL_tan.o \
		__tan.o \
		__tanf.o

#
# atan2pi.o and sincospi.o is for internal use only
#

COBJS_amd64 = \
		_TBL_atan.o \
		_TBL_exp2.o \
		_TBL_log.o \
		_TBL_log2.o \
		__tan.o \
		__tanf.o \
		_TBL_tan.o \
		copysign.o \
		exp.o \
		fabs.o \
		fmod.o \
		ilogb.o \
		isnan.o \
		nextafter.o \
		remainder.o \
		rint.o \
		scalbn.o

COBJS_sparcv9 = $(COBJS_amd64)

COBJS		= \
		$(COBJS_$(TARGET_ARCH)) \
		__cos.o \
		__lgamma.o \
		__rem_pio2.o \
		__rem_pio2m.o \
		__sin.o \
		__sincos.o \
		__xpg6.o \
		_lib_version.o \
		_SVID_error.o \
		_TBL_ipio2.o \
		_TBL_sin.o \
		acos.o \
		acosh.o \
		asin.o \
		asinh.o \
		atan.o \
		atan2.o \
		atan2pi.o \
		atanh.o \
		cbrt.o \
		ceil.o \
		cos.o \
		cosh.o \
		erf.o \
		exp10.o \
		exp2.o \
		expm1.o \
		floor.o \
		gamma.o \
		gamma_r.o \
		hypot.o \
		j0.o \
		j1.o \
		jn.o \
		lgamma.o \
		lgamma_r.o \
		log.o \
		log10.o \
		log1p.o \
		log2.o \
		logb.o \
		matherr.o \
		pow.o \
		scalb.o \
		signgam.o \
		significand.o \
		sin.o \
		sincos.o \
		sincospi.o \
		sinh.o \
		sqrt.o \
		tan.o \
		tanh.o

#
# LSARC/2003/658 adds isnanl
#
QOBJS_sparc	= \
		_TBL_atanl.o \
		_TBL_expl.o \
		_TBL_expm1l.o \
		_TBL_logl.o \
		finitel.o \
		isnanl.o

QOBJS_sparcv9	= $(QOBJS_sparc)

QOBJS_amd64	= \
		finitel.o \
		isnanl.o

#
# atan2pil.o, ieee_funcl.o, rndintl.o, sinpil.o, sincospil.o
# are for internal use only
#
# LSARC/2003/279 adds the following:
#		gammal.o	1
#		gammal_r.o	1
#		j0l.o		2
#		j1l.o		2
#		jnl.o		2
#		lgammal_r.o	1
#		scalbl.o	1
#		significandl.o	1
#
QOBJS		= \
		$(QOBJS_$(TARGET_ARCH)) \
		__cosl.o \
		__lgammal.o \
		__poly_libmq.o \
		__rem_pio2l.o \
		__sincosl.o \
		__sinl.o \
		__tanl.o \
		_TBL_cosl.o \
		_TBL_ipio2l.o \
		_TBL_sinl.o \
		_TBL_tanl.o \
		acoshl.o \
		acosl.o \
		asinhl.o \
		asinl.o \
		atan2l.o \
		atan2pil.o \
		atanhl.o \
		atanl.o \
		cbrtl.o \
		copysignl.o \
		coshl.o \
		cosl.o \
		erfl.o \
		exp10l.o \
		exp2l.o \
		expl.o \
		expm1l.o \
		fabsl.o \
		floorl.o \
		fmodl.o \
		gammal.o \
		gammal_r.o \
		hypotl.o \
		ieee_funcl.o \
		ilogbl.o \
		j0l.o \
		j1l.o \
		jnl.o \
		lgammal.o \
		lgammal_r.o \
		log10l.o \
		log1pl.o \
		log2l.o \
		logbl.o \
		logl.o \
		nextafterl.o \
		powl.o \
		remainderl.o \
		rintl.o \
		rndintl.o \
		scalbl.o \
		scalbnl.o \
		signgaml.o \
		significandl.o \
		sincosl.o \
		sincospil.o \
		sinhl.o \
		sinl.o \
		sinpil.o \
		sqrtl.o \
		tanhl.o \
		tanl.o

#
# LSARC/2003/658 adds isnanf
#
ROBJS_sparc	= \
		__cosf.o \
		__sincosf.o \
		__sinf.o \
		isnanf.o

ROBJS_sparcv9	= $(ROBJS_sparc)

ROBJS_amd64	= \
		isnanf.o \
		__cosf.o \
		__sincosf.o \
		__sinf.o

#
# atan2pif.o, sincosf.o, sincospif.o are for internal use only
#
# LSARC/2003/279 adds the following:
#		besself.o	6
#		scalbf.o	1
#		gammaf.o	1
#		gammaf_r.o	1
#		lgammaf_r.o	1
#		significandf.o	1
#
ROBJS		= \
		$(ROBJS_$(TARGET_ARCH)) \
		_TBL_r_atan_.o \
		acosf.o \
		acoshf.o \
		asinf.o \
		asinhf.o \
		atan2f.o \
		atan2pif.o \
		atanf.o \
		atanhf.o \
		besself.o \
		cbrtf.o \
		copysignf.o \
		cosf.o \
		coshf.o \
		erff.o \
		exp10f.o \
		exp2f.o \
		expf.o \
		expm1f.o \
		fabsf.o \
		floorf.o \
		fmodf.o \
		gammaf.o \
		gammaf_r.o \
		hypotf.o \
		ilogbf.o \
		lgammaf.o \
		lgammaf_r.o \
		log10f.o \
		log1pf.o \
		log2f.o \
		logbf.o \
		logf.o \
		nextafterf.o \
		powf.o \
		remainderf.o \
		rintf.o \
		scalbf.o \
		scalbnf.o \
		signgamf.o \
		significandf.o \
		sinf.o \
		sinhf.o \
		sincosf.o \
		sincospif.o \
		sqrtf.o \
		tanf.o \
		tanhf.o

#
# LSARC/2003/658 adds isnanf/isnanl
#

SOBJS_sparc 	= \
		copysign.o \
		exp.o \
		fabs.o \
		fmod.o \
		ilogb.o \
		isnan.o \
		nextafter.o \
		remainder.o \
		rint.o \
		scalbn.o

SOBJS_i386	= \
		__reduction.o \
		finitef.o \
		finitel.o \
		isnanf.o \
		isnanl.o \
		$(SOBJS_sparc)

SOBJS_amd64	= \
		__swapFLAGS.o
#		_xtoll.o \
#		_xtoull.o \


SOBJS		= \
		$(SOBJS_$(TARGET_ARCH))

complexOBJS	= \
		cabs.o \
		cabsf.o \
		cabsl.o \
		cacos.o \
		cacosf.o \
		cacosh.o \
		cacoshf.o \
		cacoshl.o \
		cacosl.o \
		carg.o \
		cargf.o \
		cargl.o \
		casin.o \
		casinf.o \
		casinh.o \
		casinhf.o \
		casinhl.o \
		casinl.o \
		catan.o \
		catanf.o \
		catanh.o \
		catanhf.o \
		catanhl.o \
		catanl.o \
		ccos.o \
		ccosf.o \
		ccosh.o \
		ccoshf.o \
		ccoshl.o \
		ccosl.o \
		cexp.o \
		cexpf.o \
		cexpl.o \
		cimag.o \
		cimagf.o \
		cimagl.o \
		clog.o \
		clogf.o \
		clogl.o \
		conj.o \
		conjf.o \
		conjl.o \
		cpow.o \
		cpowf.o \
		cpowl.o \
		cproj.o \
		cprojf.o \
		cprojl.o \
		creal.o \
		crealf.o \
		creall.o \
		csin.o \
		csinf.o \
		csinh.o \
		csinhf.o \
		csinhl.o \
		csinl.o \
		csqrt.o \
		csqrtf.o \
		csqrtl.o \
		ctan.o \
		ctanf.o \
		ctanh.o \
		ctanhf.o \
		ctanhl.o \
		ctanl.o \
		k_atan2.o \
		k_atan2l.o \
		k_cexp.o \
		k_cexpl.o \
		k_clog_r.o \
		k_clog_rl.o

OBJECTS		= $(COBJS) $(ROBJS) $(QOBJS) $(SOBJS) $(m9xOBJS) $(complexOBJS)

include		$(SRC)/lib/Makefile.lib
include 	$(LIBMDIR)/Makefile.libm.com
include		$(SRC)/lib/Makefile.rootfs

SRCDIR		= ../common/
LIBS		= $(DYNLIB) $(LINTLIB)

LINTERROFF	= -erroff=E_FUNC_SET_NOT_USED
LINTERROFF	+= -erroff=E_FUNC_RET_ALWAYS_IGNOR2
LINTERROFF	+= -erroff=E_FUNC_RET_MAYBE_IGNORED2
LINTERROFF	+= -erroff=E_IMPL_CONV_RETURN
LINTERROFF	+= -erroff=E_NAME_MULTIPLY_DEF2
LINTFLAGS	+= $(LINTERROFF)
LINTFLAGS64	+= $(LINTERROFF)
LINTFLAGS64	+= -errchk=longptr64

CPPFLAGS	+= -DLIBM_BUILD

CFLAGS 		+= $(C_BIGPICFLAGS)
CFLAGS64	+= $(C_BIGPICFLAGS)

m9x_IL		= $(LIBMDIR)/common/m9x/__fenv_$(TARGET_ARCH).il

SRCS_LD_i386_amd64 = \
	../common/LD/finitel.c \
	../common/LD/isnanl.c \
	../common/LD/nextafterl.c

SRCS_LD = \
	$(SRCS_LD_i386_$(TARGET_ARCH)) \
	../common/LD/__cosl.c \
	../common/LD/__lgammal.c \
	../common/LD/__poly_libmq.c \
	../common/LD/__rem_pio2l.c \
	../common/LD/__sincosl.c \
	../common/LD/__sinl.c \
	../common/LD/__tanl.c \
	../common/LD/_TBL_cosl.c \
	../common/LD/_TBL_ipio2l.c \
	../common/LD/_TBL_sinl.c \
	../common/LD/_TBL_tanl.c \
	../common/LD/acoshl.c \
	../common/LD/asinhl.c \
	../common/LD/atan2pil.c \
	../common/LD/atanhl.c \
	../common/LD/cbrtl.c \
	../common/LD/coshl.c \
	../common/LD/cosl.c \
	../common/LD/erfl.c \
	../common/LD/gammal.c \
	../common/LD/gammal_r.c \
	../common/LD/hypotl.c \
	../common/LD/j0l.c \
	../common/LD/j1l.c \
	../common/LD/jnl.c \
	../common/LD/lgammal.c \
	../common/LD/lgammal_r.c \
	../common/LD/log1pl.c \
	../common/LD/logbl.c \
	../common/LD/scalbl.c \
	../common/LD/signgaml.c \
	../common/LD/significandl.c \
	../common/LD/sincosl.c \
	../common/LD/sincospil.c \
	../common/LD/sinhl.c \
	../common/LD/sinl.c \
	../common/LD/sinpil.c \
	../common/LD/tanhl.c \
	../common/LD/tanl.c

SRCS_LD_i386 = \
	$(SRCS_LD)

SRCS_R_amd64 = \
	../common/R/__tanf.c \
	../common/R/isnanf.c \
	../common/R/__cosf.c \
	../common/R/__sincosf.c \
	../common/R/__sinf.c \
	../common/R/acosf.c \
	../common/R/asinf.c \
	../common/R/atan2f.c \
	../common/R/copysignf.c \
	../common/R/exp10f.c \
	../common/R/exp2f.c \
	../common/R/expm1f.c \
	../common/R/fabsf.c \
	../common/R/hypotf.c \
	../common/R/ilogbf.c \
	../common/R/log10f.c \
	../common/R/log2f.c \
	../common/R/nextafterf.c \
	../common/R/powf.c \
	../common/R/rintf.c \
	../common/R/scalbnf.c

# sparc + sparcv9
SRCS_R_sparc = \
	../common/R/__tanf.c \
	../common/R/__cosf.c \
	../common/R/__sincosf.c \
	../common/R/__sinf.c \
	../common/R/isnanf.c \
	../common/R/acosf.c \
	../common/R/asinf.c \
	../common/R/atan2f.c \
	../common/R/copysignf.c \
	../common/R/exp10f.c \
	../common/R/exp2f.c \
	../common/R/expm1f.c \
	../common/R/fabsf.c \
	../common/R/fmodf.c \
	../common/R/hypotf.c \
	../common/R/ilogbf.c \
	../common/R/log10f.c \
	../common/R/log2f.c \
	../common/R/nextafterf.c \
	../common/R/powf.c \
	../common/R/remainderf.c \
	../common/R/rintf.c \
	../common/R/scalbnf.c

SRCS_R = \
	$(SRCS_R_$(MACH)) \
	$(SRCS_R_$(TARGET_ARCH)) \
	../common/R/_TBL_r_atan_.c \
	../common/R/acoshf.c \
	../common/R/asinhf.c \
	../common/R/atan2pif.c \
	../common/R/atanf.c \
	../common/R/atanhf.c \
	../common/R/besself.c \
	../common/R/cbrtf.c \
	../common/R/cosf.c \
	../common/R/coshf.c \
	../common/R/erff.c \
	../common/R/expf.c \
	../common/R/floorf.c \
	../common/R/gammaf.c \
	../common/R/gammaf_r.c \
	../common/R/lgammaf.c \
	../common/R/lgammaf_r.c \
	../common/R/log1pf.c \
	../common/R/logbf.c \
	../common/R/logf.c \
	../common/R/scalbf.c \
	../common/R/signgamf.c \
	../common/R/significandf.c \
	../common/R/sinf.c \
	../common/R/sinhf.c \
	../common/R/sincosf.c \
	../common/R/sincospif.c \
	../common/R/sqrtf.c \
	../common/R/tanf.c \
	../common/R/tanhf.c

SRCS_Q = \
	../common/Q/_TBL_atanl.c \
	../common/Q/_TBL_expl.c \
	../common/Q/_TBL_expm1l.c \
	../common/Q/_TBL_logl.c \
	../common/Q/finitel.c \
	../common/Q/isnanl.c \
	../common/Q/__cosl.c \
	../common/Q/__lgammal.c \
	../common/Q/__poly_libmq.c \
	../common/Q/__rem_pio2l.c \
	../common/Q/__sincosl.c \
	../common/Q/__sinl.c \
	../common/Q/__tanl.c \
	../common/Q/_TBL_cosl.c \
	../common/Q/_TBL_ipio2l.c \
	../common/Q/_TBL_sinl.c \
	../common/Q/_TBL_tanl.c \
	../common/Q/acoshl.c \
	../common/Q/acosl.c \
	../common/Q/asinhl.c \
	../common/Q/asinl.c \
	../common/Q/atan2l.c \
	../common/Q/atan2pil.c \
	../common/Q/atanhl.c \
	../common/Q/atanl.c \
	../common/Q/cbrtl.c \
	../common/Q/copysignl.c \
	../common/Q/coshl.c \
	../common/Q/cosl.c \
	../common/Q/erfl.c \
	../common/Q/exp10l.c \
	../common/Q/exp2l.c \
	../common/Q/expl.c \
	../common/Q/expm1l.c \
	../common/Q/fabsl.c \
	../common/Q/floorl.c \
	../common/Q/fmodl.c \
	../common/Q/gammal.c \
	../common/Q/gammal_r.c \
	../common/Q/hypotl.c \
	../common/Q/ieee_funcl.c \
	../common/Q/ilogbl.c \
	../common/Q/j0l.c \
	../common/Q/j1l.c \
	../common/Q/jnl.c \
	../common/Q/lgammal.c \
	../common/Q/lgammal_r.c \
	../common/Q/log10l.c \
	../common/Q/log1pl.c \
	../common/Q/log2l.c \
	../common/Q/logbl.c \
	../common/Q/logl.c \
	../common/Q/nextafterl.c \
	../common/Q/powl.c \
	../common/Q/remainderl.c \
	../common/Q/rintl.c \
	../common/Q/rndintl.c \
	../common/Q/scalbl.c \
	../common/Q/scalbnl.c \
	../common/Q/signgaml.c \
	../common/Q/significandl.c \
	../common/Q/sincosl.c \
	../common/Q/sincospil.c \
	../common/Q/sinhl.c \
	../common/Q/sinl.c \
	../common/Q/sinpil.c \
	../common/Q/sqrtl.c \
	../common/Q/tanhl.c \
	../common/Q/tanl.c

SRCS_Q_sparc = \
	$(SRCS_Q)

SRCS_complex = \
	../common/complex/cabs.c \
	../common/complex/cabsf.c \
	../common/complex/cabsl.c \
	../common/complex/cacos.c \
	../common/complex/cacosf.c \
	../common/complex/cacosh.c \
	../common/complex/cacoshf.c \
	../common/complex/cacoshl.c \
	../common/complex/cacosl.c \
	../common/complex/carg.c \
	../common/complex/cargf.c \
	../common/complex/cargl.c \
	../common/complex/casin.c \
	../common/complex/casinf.c \
	../common/complex/casinh.c \
	../common/complex/casinhf.c \
	../common/complex/casinhl.c \
	../common/complex/casinl.c \
	../common/complex/catan.c \
	../common/complex/catanf.c \
	../common/complex/catanh.c \
	../common/complex/catanhf.c \
	../common/complex/catanhl.c \
	../common/complex/catanl.c \
	../common/complex/ccos.c \
	../common/complex/ccosf.c \
	../common/complex/ccosh.c \
	../common/complex/ccoshf.c \
	../common/complex/ccoshl.c \
	../common/complex/ccosl.c \
	../common/complex/cexp.c \
	../common/complex/cexpf.c \
	../common/complex/cexpl.c \
	../common/complex/cimag.c \
	../common/complex/cimagf.c \
	../common/complex/cimagl.c \
	../common/complex/clog.c \
	../common/complex/clogf.c \
	../common/complex/clogl.c \
	../common/complex/conj.c \
	../common/complex/conjf.c \
	../common/complex/conjl.c \
	../common/complex/cpow.c \
	../common/complex/cpowf.c \
	../common/complex/cpowl.c \
	../common/complex/cproj.c \
	../common/complex/cprojf.c \
	../common/complex/cprojl.c \
	../common/complex/creal.c \
	../common/complex/crealf.c \
	../common/complex/creall.c \
	../common/complex/csin.c \
	../common/complex/csinf.c \
	../common/complex/csinh.c \
	../common/complex/csinhf.c \
	../common/complex/csinhl.c \
	../common/complex/csinl.c \
	../common/complex/csqrt.c \
	../common/complex/csqrtf.c \
	../common/complex/csqrtl.c \
	../common/complex/ctan.c \
	../common/complex/ctanf.c \
	../common/complex/ctanh.c \
	../common/complex/ctanhf.c \
	../common/complex/ctanhl.c \
	../common/complex/ctanl.c \
	../common/complex/k_atan2.c \
	../common/complex/k_atan2l.c \
	../common/complex/k_cexp.c \
	../common/complex/k_cexpl.c \
	../common/complex/k_clog_r.c \
	../common/complex/k_clog_rl.c

SRCS_m9x_i386 = \
	../common/m9x/__fex_sse.c \
	../common/m9x/feprec.c \
	../common/m9x/__fex_i386.c

SRCS_m9x_i386_i386 = \
	../common/m9x/lroundf.c

SRCS_m9x_i386_amd64 = \
	../common/m9x/llrint.c \
	../common/m9x/llrintf.c \
	../common/m9x/llrintl.c \
	../common/m9x/nexttowardl.c \
	../common/m9x/remquo.c \
	../common/m9x/remquof.c \
	../common/m9x/round.c \
	../common/m9x/roundl.c \
	../common/m9x/scalbln.c \
	../common/m9x/scalblnf.c \
	../common/m9x/scalblnl.c \
	../common/m9x/trunc.c \
	../common/m9x/truncl.c

# sparc
SRCS_m9x_sparc_sparc = \
	../common/m9x/lrint.c \
	../common/m9x/lrintf.c \
	../common/m9x/lrintl.c \
	../common/m9x/lround.c \
	../common/m9x/lroundf.c \
	../common/m9x/lroundl.c

SRCS_m9x_sparc = \
	../common/m9x/__fex_sparc.c \
	../common/m9x/llrint.c \
	../common/m9x/llrintf.c \
	../common/m9x/llrintl.c \
	../common/m9x/nexttowardl.c \
	../common/m9x/remquo.c \
	../common/m9x/remquof.c \
	../common/m9x/remquol.c \
	../common/m9x/round.c \
	../common/m9x/roundl.c \
	../common/m9x/scalbln.c \
	../common/m9x/scalblnf.c \
	../common/m9x/scalblnl.c \
	../common/m9x/trunc.c \
	../common/m9x/truncl.c

SRCS_m9x = \
	$(SRCS_m9x_$(MACH)) \
	$(SRCS_m9x_sparc_$(TARGET_ARCH)) \
	$(SRCS_m9x_i386_$(TARGET_ARCH)) \
	../common/m9x/__fex_hdlr.c \
	../common/m9x/__fex_sym.c \
	../common/m9x/fdim.c \
	../common/m9x/fdimf.c \
	../common/m9x/fdiml.c \
	../common/m9x/feexcept.c \
	../common/m9x/fenv.c \
	../common/m9x/feround.c \
	../common/m9x/fex_handler.c \
	../common/m9x/fex_log.c \
	../common/m9x/fma.c \
	../common/m9x/fmaf.c \
	../common/m9x/fmal.c \
	../common/m9x/fmax.c \
	../common/m9x/fmaxf.c \
	../common/m9x/fmaxl.c \
	../common/m9x/fmin.c \
	../common/m9x/fminf.c \
	../common/m9x/fminl.c \
	../common/m9x/frexp.c \
	../common/m9x/frexpf.c \
	../common/m9x/frexpl.c \
	../common/m9x/ldexp.c \
	../common/m9x/ldexpf.c \
	../common/m9x/ldexpl.c \
	../common/m9x/llround.c \
	../common/m9x/llroundf.c \
	../common/m9x/llroundl.c \
	../common/m9x/modf.c \
	../common/m9x/modff.c \
	../common/m9x/modfl.c \
	../common/m9x/nan.c \
	../common/m9x/nanf.c \
	../common/m9x/nanl.c \
	../common/m9x/nearbyint.c \
	../common/m9x/nearbyintf.c \
	../common/m9x/nearbyintl.c \
	../common/m9x/nexttoward.c \
	../common/m9x/nexttowardf.c \
	../common/m9x/roundf.c \
	../common/m9x/tgamma.c \
	../common/m9x/tgammaf.c \
	../common/m9x/tgammal.c \
	../common/m9x/truncf.c

SRCS_C_sparc = \
	../common/C/__tan.c \
	../common/C/_TBL_atan.c \
	../common/C/_TBL_exp2.c \
	../common/C/_TBL_log.c \
	../common/C/_TBL_log2.c \
	../common/C/_TBL_tan.c \
	../common/C/acos.c \
	../common/C/asin.c \
	../common/C/atan.c \
	../common/C/atan2.c \
	../common/C/ceil.c \
	../common/C/cos.c \
	../common/C/exp.c \
	../common/C/exp10.c \
	../common/C/exp2.c \
	../common/C/expm1.c \
	../common/C/floor.c \
	../common/C/fmod.c \
	../common/C/hypot.c \
	../common/C/ilogb.c \
	../common/C/isnan.c \
	../common/C/log.c \
	../common/C/log10.c \
	../common/C/log2.c \
	../common/C/pow.c \
	../common/C/remainder.c \
	../common/C/rint.c \
	../common/C/scalbn.c \
	../common/C/sin.c \
	../common/C/sincos.c \
	../common/C/tan.c

SRCS_i386_i386 	= \
	../common/C/__libx_errno.c

SRCS_sparc_sparc = \
	$(SRCS_i386_i386)

SRCS_sparc_sparcv9 = \
	../common/C/copysign.c \
	../common/C/fabs.c \
	../common/C/nextafter.c

SRCS_i386_amd64 = \
	../common/C/_TBL_atan.c \
	../common/C/_TBL_exp2.c \
	../common/C/_TBL_log.c \
	../common/C/_TBL_log2.c \
	../common/C/__tan.c \
	../common/C/_TBL_tan.c \
	../common/C/copysign.c \
	../common/C/exp.c \
	../common/C/fabs.c \
	../common/C/ilogb.c \
	../common/C/isnan.c \
	../common/C/nextafter.c \
	../common/C/rint.c \
	../common/C/scalbn.c \
	../common/C/acos.c \
	../common/C/asin.c \
	../common/C/atan.c \
	../common/C/atan2.c \
	../common/C/ceil.c \
	../common/C/cos.c \
	../common/C/exp10.c \
	../common/C/exp2.c \
	../common/C/expm1.c \
	../common/C/floor.c \
	../common/C/hypot.c \
	../common/C/log.c \
	../common/C/log10.c \
	../common/C/log2.c \
	../common/C/pow.c \
	../common/C/sin.c \
	../common/C/sincos.c \
	../common/C/tan.c

SRCS_C = \
	$(SRCS_C_$(MACH)) \
	$(SRCS_C_i386_$(TARGET_ARCH)) \
	../common/C/__cos.c \
	../common/C/__lgamma.c \
	../common/C/__rem_pio2.c \
	../common/C/__rem_pio2m.c \
	../common/C/__sin.c \
	../common/C/__sincos.c \
	../common/C/__xpg6.c \
	../common/C/_lib_version.c \
	../common/C/_SVID_error.c \
	../common/C/_TBL_ipio2.c \
	../common/C/_TBL_sin.c \
	../common/C/acosh.c \
	../common/C/asinh.c \
	../common/C/atan2pi.c \
	../common/C/atanh.c \
	../common/C/cbrt.c \
	../common/C/cosh.c \
	../common/C/erf.c \
	../common/C/gamma.c \
	../common/C/gamma_r.c \
	../common/C/j0.c \
	../common/C/j1.c \
	../common/C/jn.c \
	../common/C/lgamma.c \
	../common/C/lgamma_r.c \
	../common/C/log1p.c \
	../common/C/logb.c \
	../common/C/matherr.c \
	../common/C/scalb.c \
	../common/C/signgam.c \
	../common/C/significand.c \
	../common/C/sincospi.c \
	../common/C/sinh.c \
	../common/C/sqrt.c \
	../common/C/tanh.c

SRCS	= \
	$(SRCS_Q_$(MACH)) \
	$(SRCS_LD_$(MACH)) \
	$(SRCS_R) \
	$(SRCS_complex) \
	$(SRCS_C)

.KEEP_STATE:

all:	$(LIBS)

lint:	lintcheck

