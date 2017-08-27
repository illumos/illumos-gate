#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

# Copyright (c) 2012, Igor Kozhukhov <ikozhukhov@gmail.com>
# Copyright (c) 2017, Chris Fraire <cfraire@me.com>.

include ../../Makefile.master

MANSECT = 	3m

MANFILES =	acos.3m \
		acosh.3m \
		asin.3m \
		asinh.3m \
		atan.3m \
		atan2.3m \
		atanh.3m \
		cabs.3m \
		cacos.3m \
		cacosh.3m \
		carg.3m \
		casin.3m \
		casinh.3m \
		catan.3m \
		catanh.3m \
		cbrt.3m \
		ccos.3m \
		ccosh.3m \
		ceil.3m \
		cexp.3m \
		cimag.3m \
		clog.3m \
		conj.3m \
		copysign.3m \
		cos.3m \
		cosh.3m \
		cpow.3m \
		cproj.3m \
		creal.3m \
		csin.3m \
		csinh.3m \
		csqrt.3m \
		ctan.3m \
		ctanh.3m \
		erf.3m \
		erfc.3m \
		exp.3m \
		exp2.3m \
		expm1.3m \
		fabs.3m \
		fdim.3m \
		feclearexcept.3m \
		fegetenv.3m \
		fegetexceptflag.3m \
		fegetround.3m \
		feholdexcept.3m \
		feraiseexcept.3m \
		fesetprec.3m \
		fetestexcept.3m \
		feupdateenv.3m \
		fex_merge_flags.3m \
		fex_set_handling.3m \
		fex_set_log.3m \
		floor.3m \
		fma.3m \
		fmax.3m \
		fmin.3m \
		fmod.3m \
		fpclassify.3m \
		frexp.3m \
		hypot.3m \
		ilogb.3m \
		isfinite.3m \
		isgreater.3m \
		isgreaterequal.3m \
		isinf.3m \
		isless.3m \
		islessequal.3m \
		islessgreater.3m \
		isnan.3m \
		isnormal.3m \
		isunordered.3m \
		j0.3m \
		ldexp.3m \
		lgamma.3m \
		llrint.3m \
		llround.3m \
		log.3m \
		log10.3m \
		log1p.3m \
		log2.3m \
		logb.3m \
		lrint.3m \
		lround.3m \
		matherr.3m \
		modf.3m \
		nan.3m \
		nearbyint.3m \
		nextafter.3m \
		pow.3m \
		remainder.3m \
		remquo.3m \
		rint.3m \
		round.3m \
		scalb.3m \
		scalbln.3m \
		signbit.3m \
		significand.3m \
		sin.3m \
		sincos.3m \
		sinh.3m \
		sqrt.3m \
		tan.3m \
		tanh.3m \
		tgamma.3m \
		trunc.3m \
		y0.3m

MANLINKS=	fesetenv.3m				\
		fesetexceptflag.3m			\
		fesetround.3m

fesetenv.3m				:= LINKSRC = fegetenv.3m

fesetexceptflag.3m			:= LINKSRC = fegetexceptflag.3m

fesetround.3m				:= LINKSRC = fegetround.3m

.KEEP_STATE:

include ../Makefile.man

install: $(ROOTMANFILES) $(ROOTMANLINKS)
