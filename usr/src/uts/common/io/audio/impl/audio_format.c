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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Purpose: Audio format conversion routines used by audio.c
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/audio/g711.h>

#include "audio_impl.h"
#include "audio_grc3.h"

extern uint_t	audio_intrhz;

/*
 * Note: In the function below, the division by the number of channels is
 * probably fairly expensive.  It turns out that we usually deal with stereo
 * or mono data, so perhaps it would be useful to build custom versions of
 * this function that only dealt with stereo or mono.
 */
static int
do_src(audio_stream_t *sp, void *p1, void *p2, int len, int nchan)
{
	int ch, size;

	/*
	 * Note that we presume that we are doing sample rate
	 * conversions on AUDIO_FORMAT_S24_NE, which means that have 4
	 * byte and 32-bit samples.
	 */
	size = sp->s_cnv_max / 4;		/* sample size is 4 */
	size /= nchan;

	for (ch = 0; ch < nchan; ch++) {
		grc3_convert(sp->s_src_state[ch], sp->s_src_quality,
		    p1, p2, len, size, nchan, ch);
	}
	return (((grc3state_t *)sp->s_src_state[0])->outsz);
}

static void
setup_src(audio_stream_t *sp, int srate, int trate, int sch, int tch)
{
	int ch, nch;

	nch = min(sch, tch);

	ASSERT(nch <= AUDIO_MAX_CHANNELS);

	if (sp->s_src_quality < 1)
		sp->s_src_quality = 1;
	if (sp->s_src_quality > 5)
		sp->s_src_quality = 5;

	for (ch = 0; ch < nch; ch++) {
		grc3_reset(sp->s_src_state[ch]);
		grc3_setup(sp->s_src_state[ch], srate, trate);
	}
}

static int
cnv_srconly(audio_stream_t *sp, int len)
{
	void *src = sp->s_cnv_src;
	void *dst = sp->s_cnv_dst;

	/*
	 * We must be using 24-bit native signed.
	 */
	len = do_src(sp, src, dst, len, sp->s_cnv_src_nchan);

	sp->s_cnv_src = dst;
	sp->s_cnv_dst = src;

	return (len);
}

static int
cnv_s24oe(audio_stream_t *sp, int len)
{
	/*
	 * Endian switch works in both directions.  We do it in place.
	 */
	int32_t *src = sp->s_cnv_src;

	for (int i = len * sp->s_cnv_src_nchan; i; i--) {
		*src = ddi_swap32(*src);
		src++;
	}

	return (len);
}


static int
cnv_from_s8(audio_stream_t *sp, int len)
{
	void *s = sp->s_cnv_src;
	void *d = sp->s_cnv_dst;
	int8_t *src = s;
	int32_t *dst = d;

	for (int i = len * sp->s_cnv_src_nchan; i; i--)
		*dst++ = (*src++) << 16;

	sp->s_cnv_src = d;
	sp->s_cnv_dst = s;
	return (len);
}

static int
cnv_from_u8(audio_stream_t *sp, int len)
{
	void *s = sp->s_cnv_src;
	void *d = sp->s_cnv_dst;
	uint8_t *src = s;
	int32_t *dst = d;

	for (int i = len * sp->s_cnv_src_nchan; i; i--)
		*dst++ = (int8_t)((*src++) ^ 0x80) << 16;

	sp->s_cnv_src = d;
	sp->s_cnv_dst = s;
	return (len);
}

static int
cnv_from_ulaw(audio_stream_t *sp, int len)
{
	void *s = sp->s_cnv_src;
	void *d = sp->s_cnv_dst;
	uint8_t *src = s;
	int32_t *dst = d;

	for (int i = len * sp->s_cnv_src_nchan; i; i--) {
		*dst++ = _8ulaw2linear16[(*src++)] << 8;
	}
	sp->s_cnv_src = d;
	sp->s_cnv_dst = s;
	return (len);
}

static int
cnv_from_alaw(audio_stream_t *sp, int len)
{
	void *s = sp->s_cnv_src;
	void *d = sp->s_cnv_dst;
	uint8_t *src = s;
	int32_t *dst = d;

	for (int i = len * sp->s_cnv_src_nchan; i; i--) {
		*dst++ = _8alaw2linear16[(*src++)] << 8;
	}
	sp->s_cnv_src = d;
	sp->s_cnv_dst = s;
	return (len);
}

static int
cnv_from_s16ne(audio_stream_t *sp, int len)
{
	void *s = sp->s_cnv_src;
	void *d = sp->s_cnv_dst;
	int16_t *src = s;
	int32_t *dst = d;

	for (int i = len * sp->s_cnv_src_nchan; i; i--)
		*dst++ = (*src++) << 8;

	sp->s_cnv_src = d;
	sp->s_cnv_dst = s;
	return (len);
}

static int
cnv_from_s16oe(audio_stream_t *sp, int len)
{
	void *s = sp->s_cnv_src;
	void *d = sp->s_cnv_dst;
	int16_t *src = s;
	int32_t *dst = d;

	for (int i = len * sp->s_cnv_src_nchan; i; i--)
		*dst++ = (int16_t)(ddi_swap16(*src++)) << 8;

	sp->s_cnv_src = d;
	sp->s_cnv_dst = s;
	return (len);
}

static int
cnv_from_u16ne(audio_stream_t *sp, int len)
{
	void *s = sp->s_cnv_src;
	void *d = sp->s_cnv_dst;
	uint16_t *src = s;
	int32_t *dst = d;

	for (int i = len * sp->s_cnv_src_nchan; i; i--)
		*dst++ = (int16_t)((*src++) ^ 0x8000) << 8;

	sp->s_cnv_src = d;
	sp->s_cnv_dst = s;
	return (len);
}

static int
cnv_from_u16oe(audio_stream_t *sp, int len)
{
	void *s = sp->s_cnv_src;
	void *d = sp->s_cnv_dst;
	uint16_t *src = s;
	int32_t *dst = d;

	for (int i = len * sp->s_cnv_src_nchan; i; i--)
		*dst++ = (int16_t)(ddi_swap16((*src++) ^ 0x8000)) << 8;

	sp->s_cnv_src = d;
	sp->s_cnv_dst = s;
	return (len);
}

static int
cnv_from_s24p(audio_stream_t *sp, int len)
{
	void *s = sp->s_cnv_src;
	void *d = sp->s_cnv_dst;
	uint8_t *src = s;
	int32_t *dst = d;
	int32_t tmp;

	for (int i = len * sp->s_cnv_src_nchan; i; i--) {
		/* NB: this is a little endian format */
		tmp = (*src++);
		tmp |= (*src++) << 8;
		tmp |= (*src++) << 16;
		*dst++ = tmp;
	}

	sp->s_cnv_src = d;
	sp->s_cnv_dst = s;
	return (len);
}

static int
cnv_from_s32ne(audio_stream_t *sp, int len)
{
	/* 32-bit conversions can be done in place */
	int32_t *src = sp->s_cnv_src;

	for (int i = len * sp->s_cnv_src_nchan; i; i--, src++)
		*src = *src >> 8;

	return (len);
}

static int
cnv_from_s32oe(audio_stream_t *sp, int len)
{
	/* 32-bit conversions can be done in place */
	int32_t *src = sp->s_cnv_src;

	for (int i = len * sp->s_cnv_src_nchan; i; i--, src++)
		*src = (int32_t)(ddi_swap32(*src)) >> 8;

	return (len);
}

/*
 * NB: All the destination format conversions use the same or fewer
 * bytes as the 24-bit unpacked (32-bits used per sample), so we can
 * convert all of them in place.
 */

static int
cnv_to_u8(audio_stream_t *sp, int len)
{
	int32_t *src = sp->s_cnv_src;
	uint8_t *dst = (void *)src;

	for (int i = len * sp->s_cnv_dst_nchan; i; i--)
		*dst++ = (*src++ >> 16) ^ 0x80;

	return (len);
}

static int
cnv_to_s8(audio_stream_t *sp, int len)
{
	int32_t *src = sp->s_cnv_src;
	int8_t *dst = (void *)src;

	for (int i = len * sp->s_cnv_dst_nchan; i; i--)
		*dst++ = *src++ >> 16;

	return (len);
}

static int
cnv_to_ulaw(audio_stream_t *sp, int len)
{
	int32_t *src = sp->s_cnv_src;
	uint8_t *dst = (void *)src;

	for (int i = len * sp->s_cnv_dst_nchan; i; i--) {
		int idx = *src++;
		idx >>= 10;
		idx += G711_ULAW_MIDPOINT;
		idx &= 0x3fff;	/* safety precaution */
		*dst++ = _14linear2ulaw8[idx];
	}

	return (len);
}

static int
cnv_to_alaw(audio_stream_t *sp, int len)
{
	int32_t *src = sp->s_cnv_src;
	uint8_t *dst = (void *)src;

	for (int i = len * sp->s_cnv_dst_nchan; i; i--) {
		int idx = *src++;
		idx >>= 11;
		idx += G711_ALAW_MIDPOINT;
		idx &= 0x1fff;	/* safety precaution */
		*dst++ = _13linear2alaw8[idx];
	}

	return (len);
}

static int
cnv_to_s16ne(audio_stream_t *sp, int len)
{
	int32_t *src = sp->s_cnv_src;
	int16_t *dst = (void *)src;

	for (int i = len * sp->s_cnv_dst_nchan; i; i--)
		*dst++ = *src++ >> 8;

	return (len);
}

static int
cnv_to_s16oe(audio_stream_t *sp, int len)
{
	int32_t *src = sp->s_cnv_src;
	int16_t *dst = (void *)src;

	for (int i = len * sp->s_cnv_dst_nchan; i; i--)
		*dst++ = ddi_swap16(*src++ >> 8);

	return (len);
}

static int
cnv_to_u16ne(audio_stream_t *sp, int len)
{
	int32_t *src = sp->s_cnv_src;
	uint16_t *dst = (void *)src;

	for (int i = len * sp->s_cnv_dst_nchan; i; i--)
		*dst++ = (*src++ >> 8) ^ 0x8000;

	return (len);
}

static int
cnv_to_u16oe(audio_stream_t *sp, int len)
{
	int32_t *src = sp->s_cnv_src;
	uint16_t *dst = (void *)src;

	for (int i = len * sp->s_cnv_dst_nchan; i; i--)
		*dst++ = ddi_swap16(*src++ >> 8) ^ 0x8000;

	return (len);
}

static int
cnv_to_s24p(audio_stream_t *sp, int len)
{
	int32_t *src = sp->s_cnv_src;
	uint8_t *dst = (void *)src;
	int32_t d;

	for (int i = len * sp->s_cnv_dst_nchan; i; i--) {
		/* NB: this is a little endian format */
		d = *src++;
		*dst++ = d & 0xff;
		*dst++ = (d >> 8) & 0xff;
		*dst++ = (d >> 16) & 0xff;
	}

	return (len);
}

static int
cnv_to_s32ne(audio_stream_t *sp, int len)
{
	int32_t *src = sp->s_cnv_src;

	for (int i = len * sp->s_cnv_dst_nchan; i; i--, src++)
		*src = *src << 8;

	return (len);
}

static int
cnv_to_s32oe(audio_stream_t *sp, int len)
{
	int32_t *src = sp->s_cnv_src;

	for (int i = len * sp->s_cnv_dst_nchan; i; i--, src++)
		*src = ddi_swap32(*src << 8);

	return (len);
}

static int
cnv_default(audio_stream_t *sp, int len)
{
	/*
	 * Note that the formats were already preverified during
	 * select_converter, to ensure that only supported formats are
	 * used.
	 */

	/*
	 * Convert samples to 24 bit (32 bit lsb aligned) if
	 * necessary.
	 */

	switch (sp->s_cnv_src_format) {

	case AUDIO_FORMAT_U8:
		len = cnv_from_u8(sp, len);
		break;

	case AUDIO_FORMAT_S8:
		len = cnv_from_s8(sp, len);
		break;

	case AUDIO_FORMAT_ULAW:
		len = cnv_from_ulaw(sp, len);
		break;

	case AUDIO_FORMAT_ALAW:
		len = cnv_from_alaw(sp, len);
		break;

	case AUDIO_FORMAT_S16_NE:
		len = cnv_from_s16ne(sp, len);
		break;

	case AUDIO_FORMAT_S16_OE:
		len = cnv_from_s16oe(sp, len);
		break;

	case AUDIO_FORMAT_U16_NE:
		len = cnv_from_u16ne(sp, len);
		break;

	case AUDIO_FORMAT_U16_OE:
		len = cnv_from_u16oe(sp, len);
		break;

	case AUDIO_FORMAT_S32_NE:
		len = cnv_from_s32ne(sp, len);
		break;

	case AUDIO_FORMAT_S32_OE:
		len = cnv_from_s32oe(sp, len);
		break;

	case AUDIO_FORMAT_S24_OE:
		len = cnv_s24oe(sp, len);
		break;

	case AUDIO_FORMAT_S24_PACKED:
		len = cnv_from_s24p(sp, len);
		break;
	}

	/*
	 * If we aren't decreasing the number of channels, then do the
	 * SRC now.  (We prefer to do SRC on the smaller number of channels.)
	 */
	if (sp->s_cnv_src_rate != sp->s_cnv_dst_rate &&
	    sp->s_cnv_src_nchan <= sp->s_cnv_dst_nchan) {
		int32_t *src = sp->s_cnv_src;
		int32_t *dst = sp->s_cnv_dst;

		len = do_src(sp, src, dst, len, sp->s_cnv_src_nchan);

		sp->s_cnv_src = dst;
		sp->s_cnv_dst = src;
	}

	/*
	 * Convert between mono and stereo
	 */

	if (sp->s_cnv_src_nchan != sp->s_cnv_dst_nchan) {
		int32_t *src = sp->s_cnv_src;
		int32_t *dst = sp->s_cnv_dst;
		int tc = sp->s_cnv_dst_nchan;
		int sc = sp->s_cnv_src_nchan;
		int nc;
		int i;

		sp->s_cnv_src = dst;
		sp->s_cnv_dst = src;

		if (sc == 1) {
			/*
			 * Mono expansion.  We expand into the stereo
			 * channel, and leave other channels silent.
			 */
			for (i = len; i; i--) {
				*dst++ = *src;
				*dst++ = *src++;
				for (int j = tc - 2; j > 0; j--) {
					*dst++ = 0;
				}

			}

		} else if (sc == 2 && tc == 1) {
			/*
			 * Stereo -> mono.  We do stereo separately to make
			 * the division fast (div by const 2 is just shift).
			 */
			for (i = len; i; i--) {
				/*
				 * Take just the left channel sample,
				 * discard the right channel.
				 */
				*dst++ = *src++;	/* left */
				src++;			/* right */
			}
		} else {
			/*
			 * Multi channel conversions.  We just copy the
			 * minimum number of channels.
			 */

			/* Calculate number of frames */

			nc = min(sc, tc);

			/* Clear destination */
			bzero(dst, (len * tc * sizeof (int32_t)));

			for (i = len; i; i--) {
				int c;

				for (c = 0; c < nc; c++)
					dst[c] = src[c];

				src += sc;
				dst += tc;
			}
		}
	}

	/*
	 * If we didn't do SRC pre-conversion, then do it now.
	 */
	if (sp->s_cnv_src_rate != sp->s_cnv_dst_rate &&
	    sp->s_cnv_src_nchan > sp->s_cnv_dst_nchan) {

		int32_t *src = sp->s_cnv_src;
		int32_t *dst = sp->s_cnv_dst;

		len = do_src(sp, src, dst, len, sp->s_cnv_dst_nchan);

		sp->s_cnv_src = dst;
		sp->s_cnv_dst = src;
	}

	/*
	 * Finally convert samples from internal 24 bit format to target format
	 */

	switch (sp->s_cnv_dst_format) {
	case AUDIO_FORMAT_U8:
		len = cnv_to_u8(sp, len);
		break;

	case AUDIO_FORMAT_S8:
		len = cnv_to_s8(sp, len);
		break;

	case AUDIO_FORMAT_S16_NE:
		len = cnv_to_s16ne(sp, len);
		break;

	case AUDIO_FORMAT_S16_OE:
		len = cnv_to_s16oe(sp, len);
		break;

	case AUDIO_FORMAT_U16_NE:
		len = cnv_to_u16ne(sp, len);
		break;

	case AUDIO_FORMAT_U16_OE:
		len = cnv_to_u16oe(sp, len);
		break;

	case AUDIO_FORMAT_S24_OE:
		len = cnv_s24oe(sp, len);
		break;

	case AUDIO_FORMAT_S24_PACKED:
		len = cnv_to_s24p(sp, len);
		break;

	case AUDIO_FORMAT_S32_NE:
		len = cnv_to_s32ne(sp, len);
		break;

	case AUDIO_FORMAT_S32_OE:
		len = cnv_to_s32oe(sp, len);
		break;

	case AUDIO_FORMAT_ULAW:
		len = cnv_to_ulaw(sp, len);
		break;

	case AUDIO_FORMAT_ALAW:
		len = cnv_to_alaw(sp, len);
		break;
	}

	return (len);
}

static const struct audio_format_info {
	unsigned		format;
	int			sampsize;
	audio_cnv_func_t	from;
	audio_cnv_func_t	to;
} audio_format_info[] = {
	{ AUDIO_FORMAT_S8,	1,	cnv_from_s8,		cnv_to_s8 },
	{ AUDIO_FORMAT_U8,	1,	cnv_from_u8,		cnv_to_u8 },
	{ AUDIO_FORMAT_ULAW,	1,	cnv_from_ulaw,		cnv_to_ulaw },
	{ AUDIO_FORMAT_ALAW,	1,	cnv_from_alaw,		cnv_to_alaw },
	{ AUDIO_FORMAT_S16_NE,	2,	cnv_from_s16ne,		cnv_to_s16ne },
	{ AUDIO_FORMAT_S16_OE,	2,	cnv_from_s16oe,		cnv_to_s16oe },
	{ AUDIO_FORMAT_U16_NE,	2,	cnv_from_u16ne,		cnv_to_u16ne },
	{ AUDIO_FORMAT_U16_OE,	2,	cnv_from_u16oe,		cnv_to_u16oe },
	{ AUDIO_FORMAT_S32_NE,	4,	cnv_from_s32ne,		cnv_to_s32ne },
	{ AUDIO_FORMAT_S32_OE,	4,	cnv_from_s32oe,		cnv_to_s32oe },

	/* 24-bit formats are "special" */
	{ AUDIO_FORMAT_S24_NE,	4,	NULL,			NULL },
	{ AUDIO_FORMAT_S24_OE,	4,	cnv_s24oe,		cnv_s24oe },
	{ AUDIO_FORMAT_S24_PACKED, 3,	cnv_from_s24p,		cnv_to_s24p },

	/* sentinel */
	{ AUDIO_FORMAT_NONE,	0,	NULL,			NULL }
};

int
auimpl_format_setup(audio_stream_t *sp, audio_parms_t *parms, uint_t mask)
{
	audio_parms_t			source;
	audio_parms_t			target;
	audio_parms_t			*uparms;
	audio_cnv_func_t		converter = NULL;
	const struct audio_format_info	*info;
	int				expand = AUDIO_UNIT_EXPAND;
	unsigned			cnv_sampsz = sizeof (uint32_t);
	unsigned			cnv_max;
	boolean_t			needsrc = B_FALSE;

	uint_t				framesz;
	uint_t				fragfr;
	uint_t				fragbytes;
	uint_t				nfrags;

	ASSERT(mutex_owned(&sp->s_lock));

	source = sp->s_cnv_src_parms;
	target = sp->s_cnv_dst_parms;

	if (sp == &sp->s_client->c_ostream) {
		if (mask & FORMAT_MSK_FMT)
			source.p_format = parms->p_format;
		if (mask & FORMAT_MSK_RATE)
			source.p_rate = parms->p_rate;
		if (mask & FORMAT_MSK_CHAN)
			source.p_nchan = parms->p_nchan;
		uparms = &source;
	} else {
		if (mask & FORMAT_MSK_FMT)
			target.p_format = parms->p_format;
		if (mask & FORMAT_MSK_RATE)
			target.p_rate = parms->p_rate;
		if (mask & FORMAT_MSK_CHAN)
			target.p_nchan = parms->p_nchan;
		uparms = &target;
	}

	/*
	 * At least one of the source or target are S24_NE.
	 *
	 * If we have a signed/native endian format, then pick an
	 * optimized converter.  While at it, ensure that a valid
	 * format is selected.
	 *
	 * After this function executes, "info" will point to the
	 * format information for the user parameters.
	 */
	if (source.p_format != AUDIO_FORMAT_S24_NE) {
		for (info = &audio_format_info[0]; info->sampsize; info++) {
			if (source.p_format == info->format) {
				converter = info->from;
				expand *= sizeof (int32_t);
				expand /= info->sampsize;
				/* save source frame size */
				cnv_sampsz = info->sampsize;
				break;
			}
		}
	} else {
		/*
		 * Target format.  Note that this case is also taken
		 * if we're operating on S24_NE data.  In that case
		 * the converter will be NULL and expand will not be
		 * altered.
		 */
		for (info = &audio_format_info[0]; info->sampsize; info++) {
			if (target.p_format == info->format) {
				converter = info->to;
				expand *= info->sampsize;
				expand /= sizeof (int32_t);
				break;
			}
		}
	}
	if (info->format == AUDIO_FORMAT_NONE) {
		audio_dev_warn(sp->s_client->c_dev, "invalid format selected");
		return (EINVAL);
	}


	ASSERT(info->sampsize);

	if (source.p_nchan != target.p_nchan) {
		/*
		 * if channels need conversion, then we must use the
		 * default.
		 */
		converter = cnv_default;
		expand *= target.p_nchan;
		expand /= source.p_nchan;
	}

	if (source.p_rate != target.p_rate) {
		needsrc = B_TRUE;
		converter = (converter == NULL) ? cnv_srconly : cnv_default;

		expand *= target.p_rate;
		expand /= source.p_rate;
	}

	/*
	 * Figure out the size of the conversion buffer we need.  We
	 * assume room for two full source fragments, which ought to
	 * be enough, even with rounding errors.
	 */
	cnv_max = 2 * (source.p_rate / audio_intrhz) *
	    cnv_sampsz * source.p_nchan;

	/*
	 * If the conversion will cause us to expand fragments, then
	 * we need to increase cnv_max.  Scale by AUDIO_UNIT_EXPAND to
	 * avoid rouding errors or losing bits when doing reducing
	 * conversions.
	 */
	if (expand > AUDIO_UNIT_EXPAND) {
		cnv_max *= expand;
		cnv_max /= AUDIO_UNIT_EXPAND;
	}

	framesz = info->sampsize * uparms->p_nchan;
	fragfr = (uparms->p_rate / audio_intrhz);
	fragbytes = fragfr * framesz;

	/*
	 * We need to "tune" the buffer and fragment counts for some
	 * uses...  OSS applications may like to configure a low
	 * latency, and they rely upon write() to block to prevent too
	 * much data from being queued up.
	 */
	if (sp->s_hintsz) {
		nfrags = sp->s_hintsz / fragbytes;
	} else if (sp->s_hintfrags) {
		nfrags = sp->s_hintfrags;
	} else {
		nfrags = sp->s_allocsz / fragbytes;
	}

	/*
	 * Now make sure that the hint works -- we need at least 2 fragments,
	 * and we need to fit within the room allocated to us.
	 */
	if (nfrags < 2) {
		nfrags = 2;
	}
	while ((nfrags * fragbytes) > sp->s_allocsz) {
		nfrags--;
	}
	/* if the resulting configuration is invalid, note it */
	if (nfrags < 2) {
		return (EINVAL);
	}

	/*
	 * Now we need to allocate space.
	 *
	 * NB: Once the allocation succeeds, we must not fail.  We are
	 * modifying the the stream settings and these changes must be
	 * made atomically.
	 */
	if (sp->s_cnv_max < cnv_max) {
		uint32_t *buf0, *buf1;

		buf0 = kmem_alloc(cnv_max, KM_NOSLEEP);
		buf1 = kmem_alloc(cnv_max, KM_NOSLEEP);
		if ((buf0 == NULL) || (buf1 == NULL)) {
			audio_dev_warn(sp->s_client->c_dev,
			    "failed to allocate audio conversion buffer "
			    "(%u bytes)", cnv_max);
			if (buf0)
				kmem_free(buf0, cnv_max);
			if (buf1)
				kmem_free(buf1, cnv_max);
			return (ENOMEM);
		}

		if (sp->s_cnv_buf0)
			kmem_free(sp->s_cnv_buf0, sp->s_cnv_max);
		if (sp->s_cnv_buf1)
			kmem_free(sp->s_cnv_buf1, sp->s_cnv_max);

		sp->s_cnv_buf0 = buf0;
		sp->s_cnv_buf1 = buf1;
		sp->s_cnv_max = cnv_max;
	}

	/* Set up the SRC state if we will be using SRC. */
	if (needsrc) {
		setup_src(sp, source.p_rate, target.p_rate,
		    source.p_nchan, target.p_nchan);
	}


	sp->s_framesz = framesz;
	sp->s_fragfr = fragfr;
	sp->s_fragbytes = fragbytes;
	sp->s_nfrags = nfrags;
	sp->s_nframes = nfrags * fragfr;
	sp->s_nbytes = sp->s_nframes * framesz;
	*sp->s_user_parms = *uparms;
	sp->s_converter = converter;

	/*
	 * Ensure that we toss any stale data -- probably wrong format.
	 * Note that as a consequence of this, all of the offsets and
	 * counters get reset.  Clients should not rely on these values
	 * being preserved when changing formats.
	 *
	 * Its critical that we reset the indices, in particular,
	 * because not only will the data be the wrong format, but the
	 * indices themselves are quite possibly going to be invalid.
	 */
	sp->s_cnv_cnt = 0;
	sp->s_tail = sp->s_head = 0;
	sp->s_tidx = sp->s_hidx = 0;

	return (0);
}

int
auimpl_format_alloc(audio_stream_t *sp)
{
	int	i;

	ASSERT(mutex_owned(&sp->s_lock));
	for (i = 0; i < AUDIO_MAX_CHANNELS; i++) {
		sp->s_src_state[i] =
		    kmem_zalloc(sizeof (grc3state_t), KM_NOSLEEP);
		if (sp->s_src_state[i] == NULL) {
			audio_dev_warn(sp->s_client->c_dev,
			    "unable to allocate SRC state structures");
			return (ENOMEM);
		}
	}
	return (0);
}

void
auimpl_format_free(audio_stream_t *sp)
{
	int	i;

	for (i = 0; i < AUDIO_MAX_CHANNELS; i++) {
		if (sp->s_src_state[i] != NULL) {
			kmem_free(sp->s_src_state[i], sizeof (grc3state_t));
			sp->s_src_state[i] = NULL;
		}
	}
}
