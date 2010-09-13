/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (C) 4Front Technologies 1996-2008.
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Purpose: GRC3 Sample Rate Converter
 *
 * GRC library version 3.1
 */

#include <sys/types.h>
#include "audio_grc3.h"

extern const int32_t filter_data_L[];
extern const int32_t filter_data_M[];
extern const int32_t filter_data_H[];
extern const int32_t filter_data_P[];

#define	filter_data_HX  filter_data_H
#define	filter_data_PX  filter_data_P

static int32_t
_muldivu64(uint32_t a, uint32_t val1, uint32_t val2)
{
	uint64_t v = ((uint64_t)a) * val1 / val2;
	return ((uint32_t)(v));
}


static int32_t
_grc_sat6(int32_t a, int32_t b)
{
	int64_t v = ((int64_t)a) * b + (1 << 5);
	return ((int32_t)(v >> 6));
}

static int32_t
_grc_sat31(int32_t a, int32_t b)
{
	int64_t v = ((int64_t)a) * b + (1 << 30);
	return ((int32_t)(v >> 31));
}


#define	DEFINE_FILTER(T)						\
static int32_t								\
_filt31_##T(int32_t a, int32_t idx)					\
{									\
	int64_t v = ((int64_t)a) * filter_data_##T[idx >> 15];		\
	return ((int32_t)(v >> 31));					\
}

#define	DEFINE_FILTER_HQ(T)						\
static int32_t								\
_filt31_##T(int32_t a, int32_t idx)					\
{									\
	int32_t idx2 = idx>>15;						\
	int64_t v = ((int64_t)a) *					\
									\
	    (filter_data_##T[idx2] +					\
	    (((int64_t)(idx & 32767)) * (filter_data_##T[idx2 + 1] -	\
	    filter_data_##T[idx2]) >> 15));				\
	return ((int32_t)(v>>31));					\
}


DEFINE_FILTER(L)
DEFINE_FILTER(M)
DEFINE_FILTER(H)
DEFINE_FILTER_HQ(HX)
DEFINE_FILTER(P)
DEFINE_FILTER_HQ(PX)

#define	DEFINE_CONVD(T, SZ)						\
static int32_t								\
_conv31d_##T(int32_t *history,  uint32_t filter, uint32_t incv)		\
{									\
	int32_t accum = 0;						\
									\
	filter = (1024 << 15) - filter;					\
									\
	while (filter < ((uint32_t)(SZ << 15))) {			\
		accum += _filt31_##T(*history, filter);			\
		filter += incv;						\
		history--;						\
	}								\
									\
	return (accum);							\
}

DEFINE_CONVD(L, 4096)
DEFINE_CONVD(M, 8192)
DEFINE_CONVD(H, 16384)
DEFINE_CONVD(HX, 16384)
DEFINE_CONVD(P, 32768)
DEFINE_CONVD(PX, 32768)

static int32_t
_conv31_L(int32_t *history, uint32_t filter)
{
	int32_t accum = 0;

#define	ITERATION(p)				\
	accum += _filt31_##p(*history, filter);	\
	filter += (1024 << 15);			\
	history--

	ITERATION(L); ITERATION(L); ITERATION(L); ITERATION(L);
	return (accum);
}


static int32_t
_conv31_M(int32_t *history, uint32_t filter)
{
	int32_t accum = 0;

	ITERATION(M); ITERATION(M); ITERATION(M); ITERATION(M);
	ITERATION(M); ITERATION(M); ITERATION(M); ITERATION(M);
	return (accum);
}

static int32_t
_conv31_H(int32_t *history, uint32_t filter)
{
	int32_t accum = 0;

	ITERATION(H); ITERATION(H); ITERATION(H); ITERATION(H);
	ITERATION(H); ITERATION(H); ITERATION(H); ITERATION(H);
	ITERATION(H); ITERATION(H); ITERATION(H); ITERATION(H);
	ITERATION(H); ITERATION(H); ITERATION(H); ITERATION(H);
	return (accum);
}

static int32_t
_conv31_HX(int32_t *history, uint32_t filter)
{
	int32_t accum = 0;

	ITERATION(HX); ITERATION(HX); ITERATION(HX); ITERATION(HX);
	ITERATION(HX); ITERATION(HX); ITERATION(HX); ITERATION(HX);
	ITERATION(HX); ITERATION(HX); ITERATION(HX); ITERATION(HX);
	ITERATION(HX); ITERATION(HX); ITERATION(HX); ITERATION(HX);
	return (accum);
}

static int32_t
_conv31_P(int32_t *history, uint32_t filter)
{
	int32_t accum = 0;

	ITERATION(P); ITERATION(P); ITERATION(P); ITERATION(P);
	ITERATION(P); ITERATION(P); ITERATION(P); ITERATION(P);
	ITERATION(P); ITERATION(P); ITERATION(P); ITERATION(P);
	ITERATION(P); ITERATION(P); ITERATION(P); ITERATION(P);
	ITERATION(P); ITERATION(P); ITERATION(P); ITERATION(P);
	ITERATION(P); ITERATION(P); ITERATION(P); ITERATION(P);
	ITERATION(P); ITERATION(P); ITERATION(P); ITERATION(P);
	ITERATION(P); ITERATION(P); ITERATION(P); ITERATION(P);
	return (accum);
}

static int32_t
_conv31_PX(int32_t *history, uint32_t filter)
{
	int32_t accum = 0;

	ITERATION(PX); ITERATION(PX); ITERATION(PX); ITERATION(PX);
	ITERATION(PX); ITERATION(PX); ITERATION(PX); ITERATION(PX);
	ITERATION(PX); ITERATION(PX); ITERATION(PX); ITERATION(PX);
	ITERATION(PX); ITERATION(PX); ITERATION(PX); ITERATION(PX);
	ITERATION(PX); ITERATION(PX); ITERATION(PX); ITERATION(PX);
	ITERATION(PX); ITERATION(PX); ITERATION(PX); ITERATION(PX);
	ITERATION(PX); ITERATION(PX); ITERATION(PX); ITERATION(PX);
	ITERATION(PX); ITERATION(PX); ITERATION(PX); ITERATION(PX);
	return (accum);
}

#define	GRC3_RESAMPLE(QUAL)						\
static void								\
grc3_upsample_##QUAL(grc3state_t *grc, const int32_t *src,		\
    int32_t *dst, uint32_t sz, uint32_t bufsz, int inc, int offset)	\
{									\
	int32_t ptr = grc->ptr;						\
	int32_t srcrate = grc->srcrate;					\
	int32_t dstrate = grc->dstrate;					\
	int32_t *history = grc->historyptr;				\
	int32_t filtfactor = grc->filtfactor;				\
	uint32_t dstsz = 0;						\
									\
	src += offset;							\
	dst += offset;							\
									\
	while (sz > 0) {						\
		while (ptr < dstrate) {					\
			if (dstsz >= bufsz)				\
				goto endloop;				\
			dst[0] = (_conv31_##QUAL(history,		\
				_grc_sat6(ptr, filtfactor)));		\
			ptr += srcrate;					\
			dst += inc;					\
			dstsz++;					\
		}							\
									\
		history++;						\
		if (history >= (grc->history + GRC3_MAXHISTORY * 2))	\
			history -= GRC3_MAXHISTORY;			\
									\
		history[0] = history[-GRC3_MAXHISTORY] = (*src);	\
									\
		ptr -= dstrate;						\
									\
		sz--;							\
		src += inc;						\
	}								\
endloop:								\
									\
	grc->ptr = ptr;							\
	grc->historyptr = history;					\
	grc->outsz = dstsz;						\
}									\
									\
static void								\
grc3_dnsample_##QUAL(grc3state_t *grc, const int32_t *src,		\
    int32_t *dst, uint32_t sz, uint32_t bufsz, int inc, int offset)	\
{									\
	int32_t ptr = grc->ptr;						\
	int32_t srcrate = grc->srcrate;					\
	int32_t dstrate = grc->dstrate;					\
	int32_t sat = grc->sat;						\
	int32_t *history = grc->historyptr;				\
	int32_t filtfactor = grc->filtfactor;				\
	uint32_t dstsz = 0;						\
									\
	src += offset;							\
	dst += offset;							\
									\
	while (sz > 0) {						\
		while (ptr >= srcrate) {				\
			if (dstsz >= bufsz)				\
				goto endloop;				\
			ptr -= srcrate;					\
			dst[0] = (_conv31d_##QUAL(history,		\
			    _grc_sat6(ptr, filtfactor),			\
				grc->ptr_incv));			\
			dst += inc;					\
			dstsz++;					\
		}							\
									\
		history++;						\
		if (history >= (grc->history + GRC3_MAXHISTORY * 2))	\
			history -= GRC3_MAXHISTORY;			\
									\
		/*							\
		 * TODO: for better quality multiplier is worth moving	\
		 * to output cascade					\
		 */							\
		history[0] = history[-GRC3_MAXHISTORY] =		\
		    _grc_sat31((*src), sat);				\
									\
		ptr += dstrate;						\
									\
		sz--;							\
		src += inc;						\
	}								\
endloop:								\
									\
	grc->ptr = ptr;							\
	grc->historyptr = history;					\
	grc->outsz = dstsz;						\
}									\
									\
static void								\
grc3_resample_##QUAL(grc3state_t *grc, const void *src, void *dst,	\
    uint32_t sz, uint32_t bufsz, int inc, int  offset)			\
{									\
	if (grc->srcrate <= grc->dstrate)				\
		grc3_upsample_##QUAL(grc, src, dst, sz,			\
		    bufsz, inc, offset);				\
	else								\
		grc3_dnsample_##QUAL(grc, src, dst, sz,			\
		    bufsz, inc, offset);				\
}

GRC3_RESAMPLE(L)
GRC3_RESAMPLE(M)
GRC3_RESAMPLE(H)
GRC3_RESAMPLE(HX)
GRC3_RESAMPLE(P)
GRC3_RESAMPLE(PX)

/*
 * For performance reasons, we only support 24-bit SRC.
 */
void
grc3_convert(grc3state_t *grc, int quality, const void *src,
    void *dst, int sz, int bufsz, int inc, int offset)
{

	switch (quality) {
	default:
	case 0:
	case 1:
		grc3_resample_L(grc, src, dst, sz, bufsz, inc, offset);
		break;
	case 2:
		grc3_resample_M(grc, src, dst, sz, bufsz, inc, offset);
		break;
	case 3:
		grc3_resample_H(grc, src, dst, sz, bufsz, inc, offset);
		break;
	case 4:
		grc3_resample_HX(grc, src, dst, sz, bufsz, inc, offset);
		break;
	case 5:
		grc3_resample_P(grc, src, dst, sz, bufsz, inc, offset);
		break;
	case 6:
		grc3_resample_PX(grc, src, dst, sz, bufsz, inc, offset);
		break;
	}
}

void
grc3_reset(grc3state_t *grc)
{
	int32_t t;
	grc->ptr = 0;
	grc->historyptr = grc->history + GRC3_MAXHISTORY;

	for (t = 0; t < GRC3_MAXHISTORY * 2; t++)
		grc->history[t] = 0;
}

static void
grc3_setup_up(grc3state_t *grc, uint32_t fromRate, uint32_t toRate)
{
	grc->srcrate = fromRate;
	grc->dstrate = toRate;
	grc->filtfactor = 0x80000000U / toRate;
}

static void
grc3_setup_dn(grc3state_t *grc, uint32_t fromRate, uint32_t toRate)
{
	grc->srcrate = fromRate;
	grc->dstrate = toRate;
	grc->filtfactor = 0x80000000U / fromRate;
	grc->ptr_incv = _muldivu64(1024 << 15, toRate, fromRate);
	grc->sat = _muldivu64(0x80000000U, toRate, fromRate);
}

void
grc3_setup(grc3state_t *grc, uint32_t fromRate, uint32_t toRate)
{
	while ((!(fromRate & 1)) && (!(toRate & 1)) && (fromRate > 0)) {
		fromRate >>= 1;
		toRate >>= 1;
	}

	if (fromRate <= toRate)
		grc3_setup_up(grc, fromRate, toRate);
	else
		grc3_setup_dn(grc, fromRate, toRate);
}
