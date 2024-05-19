/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1992-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * Description:
 *
 * g723_init_state(), g723_encode(), g723_decode()
 *
 * These routines comprise an implementation of the CCITT G.723 ADPCM coding
 * algorithm.  Essentially, this implementation is identical to
 * the bit level description except for a few deviations which
 * take advantage of work station attributes, such as hardware 2's
 * complement arithmetic and large memory. Specifically, certain time
 * consuming operations such as multiplications are replaced
 * with look up tables and software 2's complement operations are
 * replaced with hardware 2's complement.
 *
 * The deviation (look up tables) from the bit level
 * specification, preserves the bit level performance specifications.
 *
 * As outlined in the G.723 Recommendation, the algorithm is broken
 * down into modules.  Each section of code below is preceded by
 * the name of the module which it is implementing.
 *
 */
#include <stdlib.h>
#include <libaudio.h>

/*
 * g723_tables.c
 *
 * Description:
 *
 * This file contains statically defined lookup tables for
 * use with the G.723 coding routines.
 */

/*
 * Maps G.723 code word to reconstructed scale factor normalized log
 * magnitude values.
 */
static short	_dqlntab[8] = {-2048, 135, 273, 373, 373, 273, 135, -2048};

/* Maps G.723 code word to log of scale factor multiplier. */
static short	_witab[8] = {-128, 960, 4384, 18624, 18624, 4384, 960, -128};

/*
 * Maps G.723 code words to a set of values whose long and short
 * term averages are computed and then compared to give an indication
 * how stationary (steady state) the signal is.
 */
static short	_fitab[8] = {0, 0x200, 0x400, 0xE00, 0xE00, 0x400, 0x200, 0};

/*
 * g723_init_state()
 *
 * Description:
 *
 * This routine initializes and/or resets the audio_encode_state structure
 * pointed to by 'state_ptr'.
 * All the state initial values are specified in the G.723 standard specs.
 */
void
g723_init_state(
	struct audio_g72x_state *state_ptr)
{
	int cnta;

	state_ptr->yl = 34816;
	state_ptr->yu = 544;
	state_ptr->dms = 0;
	state_ptr->dml = 0;
	state_ptr->ap = 0;
	for (cnta = 0; cnta < 2; cnta++) {
		state_ptr->a[cnta] = 0;
		state_ptr->pk[cnta] = 0;
		state_ptr->sr[cnta] = 32;
	}
	for (cnta = 0; cnta < 6; cnta++) {
		state_ptr->b[cnta] = 0;
		state_ptr->dq[cnta] = 32;
	}
	state_ptr->td = 0;
	state_ptr->leftover_cnt = 0;		/* no left over codes */
}

/*
 * _g723_fmult()
 *
 * returns the integer product of the "floating point" an and srn
 * by the lookup table _fmultwanmant[].
 *
 */
static int
_g723_fmult(
		int an,
		int srn)
{
	short	anmag, anexp, anmant;
	short	wanexp;

	if (an == 0) {
		return ((srn >= 0) ?
		    ((srn & 077) + 1) >> (18 - (srn >> 6)) :
		    -(((srn & 077) + 1) >> (2 - (srn >> 6))));
	} else if (an > 0) {
		anexp = _fmultanexp[an] - 12;
		anmant = ((anexp >= 0) ? an >> anexp : an << -anexp) & 07700;
		if (srn >= 0) {
			wanexp = anexp + (srn >> 6) - 7;
			return ((wanexp >= 0) ?
			    (_fmultwanmant[(srn & 077) + anmant] << wanexp)
			    & 0x7FFF :
			    _fmultwanmant[(srn & 077) + anmant] >> -wanexp);
		} else {
			wanexp = anexp + (srn >> 6) - 0xFFF7;
			return ((wanexp >= 0) ?
			    -((_fmultwanmant[(srn & 077) + anmant] << wanexp)
			    & 0x7FFF) :
			    -(_fmultwanmant[(srn & 077) + anmant] >> -wanexp));
		}
	} else {
		anmag = (-an) & 0x1FFF;
		anexp = _fmultanexp[anmag] - 12;
		anmant = ((anexp >= 0) ? anmag >> anexp : anmag << -anexp)
		    & 07700;
		if (srn >= 0) {
			wanexp = anexp + (srn >> 6) - 7;
			return ((wanexp >= 0) ?
			    -((_fmultwanmant[(srn & 077) + anmant] << wanexp)
			    & 0x7FFF) :
			    -(_fmultwanmant[(srn & 077) + anmant] >> -wanexp));
		} else {
			wanexp = anexp + (srn >> 6) - 0xFFF7;
			return ((wanexp >= 0) ?
			    (_fmultwanmant[(srn & 077) + anmant] << wanexp)
			    & 0x7FFF :
			    _fmultwanmant[(srn & 077) + anmant] >> -wanexp);
		}
	}

}

/*
 * _g723_update()
 *
 * updates the state variables for each output code
 *
 */
static void
_g723_update(
	int	y,
	int	i,
	int	dq,
	int	sr,
	int	pk0,
	struct audio_g72x_state *state_ptr,
	int	sigpk)
{
	int	cnt;
	long	fi;			/* Adaptation speed control, FUNCTF */
	short	mag, exp;		/* Adaptive predictor, FLOAT A */
	short	a2p;			/* LIMC */
	short	a1ul;			/* UPA1 */
	short	pks1, fa1;		/* UPA2 */
	char	tr;			/* tone/transition detector */
	short	thr2;

	mag = dq & 0x3FFF;
	/* TRANS */
	if (state_ptr->td == 0)
		tr = 0;
	else if (state_ptr->yl > 0x40000)
		tr = (mag <= 0x2F80) ? 0 : 1;
	else {
		thr2 = (0x20 + ((state_ptr->yl >> 10) & 0x1F)) <<
		    (state_ptr->yl >> 15);
		if (mag >= thr2)
			tr = 1;
		else
			tr = (mag <= (thr2 - (thr2 >> 2))) ? 0 : 1;
	}

	/*
	 * Quantizer scale factor adaptation.
	 */

	/* FUNCTW & FILTD & DELAY */
	state_ptr->yu = y + ((_witab[i] - y) >> 5);

	/* LIMB */
	if (state_ptr->yu < 544)
		state_ptr->yu = 544;
	else if (state_ptr->yu > 5120)
		state_ptr->yu = 5120;

	/* FILTE & DELAY */
	state_ptr->yl += state_ptr->yu + ((-state_ptr->yl) >> 6);

	/*
	 * Adaptive predictor coefficients.
	 */
	if (tr == 1) {
		state_ptr->a[0] = 0;
		state_ptr->a[1] = 0;
		state_ptr->b[0] = 0;
		state_ptr->b[1] = 0;
		state_ptr->b[2] = 0;
		state_ptr->b[3] = 0;
		state_ptr->b[4] = 0;
		state_ptr->b[5] = 0;
	} else {

		/* UPA2 */
		pks1 = pk0 ^ state_ptr->pk[0];

		a2p = state_ptr->a[1] - (state_ptr->a[1] >> 7);
		if (sigpk == 0) {
			fa1 = (pks1) ? state_ptr->a[0] : -state_ptr->a[0];
			if (fa1 < -8191)
				a2p -= 0x100;
			else if (fa1 > 8191)
				a2p += 0xFF;
			else
				a2p += fa1 >> 5;

			if (pk0 ^ state_ptr->pk[1])
				/* LIMC */
				if (a2p <= -12160)
					a2p = -12288;
				else if (a2p >= 12416)
					a2p = 12288;
				else
					a2p -= 0x80;
			else if (a2p <= -12416)
				a2p = -12288;
			else if (a2p >= 12160)
				a2p = 12288;
			else
				a2p += 0x80;
		}

		/* TRIGB & DELAY */
		state_ptr->a[1] = a2p;

		/* UPA1 */
		state_ptr->a[0] -= state_ptr->a[0] >> 8;
		if (sigpk == 0) {
			if (pks1 == 0) {
				state_ptr->a[0] += 192;
			} else {
				state_ptr->a[0] -= 192;
			}
		}

		/* LIMD */
		a1ul = 15360 - a2p;
		if (state_ptr->a[0] < -a1ul)
			state_ptr->a[0] = -a1ul;
		else if (state_ptr->a[0] > a1ul)
			state_ptr->a[0] = a1ul;

		/* UPB : update of b's */
		for (cnt = 0; cnt < 6; cnt++) {
			state_ptr->b[cnt] -= state_ptr->b[cnt] >> 8;
			if (dq & 0x3FFF) {
				/* XOR */
				if ((dq ^ state_ptr->dq[cnt]) >= 0)
					state_ptr->b[cnt] += 128;
				else
					state_ptr->b[cnt] -= 128;
			}
		}
	}

	for (cnt = 5; cnt > 0; cnt--)
		state_ptr->dq[cnt] = state_ptr->dq[cnt-1];
	/* FLOAT A */
	if (mag == 0) {
		state_ptr->dq[0] = (dq >= 0) ? 0x20 : 0xFC20;
	} else {
		exp = _fmultanexp[mag];
		state_ptr->dq[0] = (dq >= 0) ?
		    (exp << 6) + ((mag << 6) >> exp) :
		    (exp << 6) + ((mag << 6) >> exp) - 0x400;
	}

	state_ptr->sr[1] = state_ptr->sr[0];
	/* FLOAT B */
	if (sr == 0) {
		state_ptr->sr[0] = 0x20;
	} else if (sr > 0) {
		exp = _fmultanexp[sr];
		state_ptr->sr[0] = (exp << 6) + ((sr << 6) >> exp);
	} else {
		mag = -sr;
		exp = _fmultanexp[mag];
		state_ptr->sr[0] =  (exp << 6) + ((mag << 6) >> exp) - 0x400;
	}

	/* DELAY A */
	state_ptr->pk[1] = state_ptr->pk[0];
	state_ptr->pk[0] = pk0;

	/* TONE */
	if (tr == 1)
		state_ptr->td = 0;
	else if (a2p < -11776)
		state_ptr->td = 1;
	else
		state_ptr->td = 0;

	/*
	 * Adaptation speed control.
	 */
	fi = _fitab[i];						/* FUNCTF */
	state_ptr->dms += (fi - state_ptr->dms) >> 5;		/* FILTA */
	state_ptr->dml += (((fi << 2) - state_ptr->dml) >> 7);	/* FILTB */

	if (tr == 1)
		state_ptr->ap = 256;
	else if (y < 1536)					/* SUBTC */
		state_ptr->ap += (0x200 - state_ptr->ap) >> 4;
	else if (state_ptr->td == 1)
		state_ptr->ap += (0x200 - state_ptr->ap) >> 4;
	else if (abs((state_ptr->dms << 2) - state_ptr->dml) >=
	    (state_ptr->dml >> 3))
		state_ptr->ap += (0x200 - state_ptr->ap) >> 4;
	else
		state_ptr->ap += (-state_ptr->ap) >> 4;
}

/*
 * _g723_quantize()
 *
 * Description:
 *
 * Given a raw sample, 'd', of the difference signal and a
 * quantization step size scale factor, 'y', this routine returns the
 * G.723 codeword to which that sample gets quantized.  The step
 * size scale factor division operation is done in the log base 2 domain
 * as a subtraction.
 */
static unsigned int
_g723_quantize(
	int	d,	/* Raw difference signal sample. */
	int	y)	/* Step size multiplier. */
{
	/* LOG */
	short	dqm;	/* Magnitude of 'd'. */
	short	exp;	/* Integer part of base 2 log of magnitude of 'd'. */
	short	mant;	/* Fractional part of base 2 log. */
	short	dl;	/* Log of magnitude of 'd'. */

	/* SUBTB */
	short	dln;	/* Step size scale factor normalized log. */

	/* QUAN */
	unsigned char	i;	/* G.723 codeword. */

	/*
	 * LOG
	 *
	 * Compute base 2 log of 'd', and store in 'dln'.
	 *
	 */
	dqm = abs(d);
	exp = _fmultanexp[dqm >> 1];
	mant = ((dqm << 7) >> exp) & 0x7F;	/* Fractional portion. */
	dl = (exp << 7) + mant;

	/*
	 * SUBTB
	 *
	 * "Divide" by step size multiplier.
	 */
	dln = dl - (y >> 2);

	/*
	 * QUAN
	 *
	 * Obtain codword for 'd'.
	 */
	i = _g723quani[dln & 0xFFF];
	if (d < 0)
		i ^= 7;		/* Stuff in sign of 'd'. */
	else if (i == 0)
		i = 7;		/* New in 1988 revision */

	return (i);
}

/*
 * _g723_reconstr()
 *
 * Description:
 *
 * Returns reconstructed difference signal 'dq' obtained from
 * G.723 codeword 'i' and quantization step size scale factor 'y'.
 * Multiplication is performed in log base 2 domain as addition.
 */
static int
_g723_reconstr(
	int		i,	/* G.723 codeword. */
	unsigned long	y)	/* Step size multiplier. */
{
	/* ADD A */
	short	dql;	/* Log of 'dq' magnitude. */

	/* ANTILOG */
	short	dex;	/* Integer part of log. */
	short	dqt;
	short	dq;	/* Reconstructed difference signal sample. */


	dql = _dqlntab[i] + (y >> 2);	/* ADDA */

	if (dql < 0)
		dq = 0;
	else {				/* ANTILOG */
		dex = (dql >> 7) & 15;
		dqt = 128 + (dql & 127);
		dq = (dqt << 7) >> (14 - dex);
	}
	if (i & 4)
		dq -= 0x8000;

	return (dq);
}

/*
 * _tandem_adjust(sr, se, y, i)
 *
 * Description:
 *
 * At the end of ADPCM decoding, it simulates an encoder which may be receiving
 * the output of this decoder as a tandem process. If the output of the
 * simulated encoder differs from the input to this decoder, the decoder output
 * is adjusted by one level of A-law or Mu-law codes.
 *
 * Input:
 *	sr	decoder output linear PCM sample,
 *	se	predictor estimate sample,
 *	y	quantizer step size,
 *	i	decoder input code
 *
 * Return:
 *	adjusted A-law or Mu-law compressed sample.
 */
static int
_tandem_adjust_alaw(
	int	sr,	/* decoder output linear PCM sample */
	int	se,	/* predictor estimate sample */
	int	y,	/* quantizer step size */
	int	i)	/* decoder input code */
{
	unsigned char	sp;	/* A-law compressed 8-bit code */
	short	dx;		/* prediction error */
	char	id;		/* quantized prediction error */
	int	sd;		/* adjusted A-law decoded sample value */
	int	im;		/* biased magnitude of i */
	int	imx;		/* biased magnitude of id */

	sp = audio_s2a((sr <= -0x2000)? -0x8000 :
	    (sr < 0x1FFF)? sr << 2 : 0x7FFF); /* short to A-law compression */
	dx = (audio_a2s(sp) >> 2) - se;  /* 16-bit prediction error */
	id = _g723_quantize(dx, y);

	if (id == i)			/* no adjustment on sp */
		return (sp);
	else {				/* sp adjustment needed */
		im = i ^ 4;		/* 2's complement to biased unsigned */
		imx = id ^ 4;

		if (imx > im) {		/* sp adjusted to next lower value */
			if (sp & 0x80)
				sd = (sp == 0xD5)? 0x55 :
				    ((sp ^ 0x55) - 1) ^ 0x55;
			else
				sd = (sp == 0x2A)? 0x2A :
				    ((sp ^ 0x55) + 1) ^ 0x55;
		} else {	/* sp adjusted to next higher value */
			if (sp & 0x80)
				sd = (sp == 0xAA)? 0xAA :
				    ((sp ^ 0x55) + 1) ^ 0x55;
			else
				sd = (sp == 0x55)? 0xD5 :
				    ((sp ^ 0x55) - 1) ^ 0x55;
		}
		return (sd);
	}
}

static int
_tandem_adjust_ulaw(
	int	sr,		/* decoder output linear PCM sample */
	int	se,		/* predictor estimate sample */
	int	y,		/* quantizer step size */
	int	i)		/* decoder input code */
{
	unsigned char   sp;	/* A-law compressed 8-bit code */
	short	dx;		/* prediction error */
	char	id;		/* quantized prediction error */
	int	sd;		/* adjusted A-law decoded sample value */
	int	im;		/* biased magnitude of i */
	int	imx;		/* biased magnitude of id */

	sp = audio_s2u((sr <= -0x2000)? -0x8000 :
	    (sr >= 0x1FFF)? 0x7FFF : sr << 2); /* short to u-law compression */
	dx = (audio_u2s(sp) >> 2) - se;  /* 16-bit prediction error */
	id = _g723_quantize(dx, y);
	if (id == i)
		return (sp);
	else {
		/* ADPCM codes : 8, 9, ... F, 0, 1, ... , 6, 7 */
		im = i ^ 4;		/* 2's complement to biased unsigned */
		imx = id ^ 4;

		/* u-law codes : 0, 1, ... 7E, 7F, FF, FE, ... 81, 80 */
		if (imx > im) {		/* sp adjusted to next lower value */
			if (sp & 0x80)
				sd = (sp == 0xFF)? 0x7E : sp + 1;
			else
				sd = (sp == 0)? 0 : sp - 1;

		} else {		/* sp adjusted to next higher value */
			if (sp & 0x80)
				sd = (sp == 0x80)? 0x80 : sp - 1;
			else
				sd = (sp == 0x7F)? 0xFE : sp + 1;
		}
		return (sd);
	}
}

static unsigned char
_encoder(
	int		sl,
	struct audio_g72x_state *state_ptr)
{
	short	sei, sezi, se, sez;	/* ACCUM */
	short	d;			/* SUBTA */
	float	al;		/* use floating point for faster multiply */
	short	y, dif;			/* MIX */
	short	sr;			/* ADDB */
	short	pk0, sigpk, dqsez;	/* ADDC */
	short	dq, i;
	int	cnt;

	/* ACCUM */
	sezi = _g723_fmult(state_ptr->b[0] >> 2, state_ptr->dq[0]);
	for (cnt = 1; cnt < 6; cnt++)
		sezi = sezi + _g723_fmult(state_ptr->b[cnt] >> 2,
		    state_ptr->dq[cnt]);
	sei = sezi;
	for (cnt = 1; cnt > -1; cnt--)
		sei = sei + _g723_fmult(state_ptr->a[cnt] >> 2,
		    state_ptr->sr[cnt]);
	sez = sezi >> 1;
	se = sei >> 1;

	d = sl - se;					/* SUBTA */

	if (state_ptr->ap >= 256)
		y = state_ptr->yu;
	else {
		y = state_ptr->yl >> 6;
		dif = state_ptr->yu - y;
		al = state_ptr->ap >> 2;
		if (dif > 0)
			y += ((int)(dif * al)) >> 6;
		else if (dif < 0)
			y += ((int)(dif * al) + 0x3F) >> 6;
	}

	i = _g723_quantize(d, y);
	dq = _g723_reconstr(i, y);

	sr = (dq < 0) ? se - (dq & 0x3FFF) : se + dq;	/* ADDB */

	dqsez = sr + sez - se;				/* ADDC */
	if (dqsez == 0) {
		pk0 = 0;
		sigpk = 1;
	} else {
		pk0 = (dqsez < 0) ? 1 : 0;
		sigpk = 0;
	}

	_g723_update(y, i, dq, sr, pk0, state_ptr, sigpk);

	return (i);
}

/*
 * g723_encode()
 *
 * Description:
 *
 * Encodes a buffer of linear PCM, A-law or Mu-law data pointed to by 'in_buf'
 * according the G.723 encoding algorithm and packs the resulting code words
 * into bytes. The bytes of codewords are written to a buffer
 * pointed to by 'out_buf'.
 *
 * Notes:
 *
 * In the event that the number packed codes is shorter than a sample unit,
 * the remainder is saved in the state stucture till next call.  It is then
 * packed into the new buffer on the next call.
 * The number of valid bytes in 'out_buf' is returned in *out_size.  Note that
 * this will not always be equal to 3/8 of 'data_size' on input. On the
 * final call to 'g723_encode()' the calling program might want to
 * check if any code bits was left over.  This can be
 * done by calling 'g723_encode()' with data_size = 0, which returns in
 * *out_size a* 0 if nothing was leftover and the number of bits left over in
 * the state structure which now is in out_buf[0].
 *
 * The 3 lower significant bits of an individual byte in the output byte
 * stream is packed with a G.723 code first.  Then the 3 higher order
 * bits are packed with the next code.
 */
int
g723_encode(
	void		*in_buf,
	int		data_size,
	Audio_hdr	*in_header,
	unsigned char	*out_buf,
	int		*out_size,
	struct audio_g72x_state	*state_ptr)
{
	int		i;
	unsigned char	*out_ptr;
	unsigned char	*leftover;
	unsigned int	bits;
	unsigned int	codes;
	int		offset;
	short		*short_ptr;
	unsigned char	*char_ptr;

	/* Dereference the array pointer for faster access */
	leftover = &state_ptr->leftover[0];

	/* Return all cached leftovers */
	if (data_size == 0) {
		for (i = 0; state_ptr->leftover_cnt > 0; i++) {
			*out_buf++ = leftover[i];
			state_ptr->leftover_cnt -= 8;
		}
		if (i > 0) {
			/* Round up to a complete sample unit */
			for (; i < 3; i++)
				*out_buf++ = 0;
		}
		*out_size = i;
		state_ptr->leftover_cnt = 0;
		return (AUDIO_SUCCESS);
	}

	/* XXX - if linear, it had better be 16-bit! */
	if (in_header->encoding == AUDIO_ENCODING_LINEAR) {
		if (data_size & 1) {
			return (AUDIO_ERR_BADFRAME);
		} else {
			data_size >>= 1;
			short_ptr = (short *)in_buf;
		}
	} else {
		char_ptr = (unsigned char *)in_buf;
	}
	out_ptr = (unsigned char *)out_buf;

	offset = state_ptr->leftover_cnt / 8;
	bits = state_ptr->leftover_cnt % 8;
	codes = (bits > 0) ? leftover[offset] : 0;

	while (data_size--) {
		switch (in_header->encoding) {
		case AUDIO_ENCODING_LINEAR:
			i = _encoder(*short_ptr++ >> 2, state_ptr);
			break;
		case AUDIO_ENCODING_ALAW:
			i = _encoder(audio_a2s(*char_ptr++) >> 2, state_ptr);
			break;
		case AUDIO_ENCODING_ULAW:
			i = _encoder(audio_u2s(*char_ptr++) >> 2, state_ptr);
			break;
		default:
			return (AUDIO_ERR_ENCODING);
		}
		/* pack the resulting code into leftover buffer */
		codes += i << bits;
		bits += 3;
		if (bits >= 8) {
			leftover[offset] = codes & 0xff;
			bits -= 8;
			codes >>= 8;
			offset++;
		}
		state_ptr->leftover_cnt += 3;

		/* got a whole sample unit so copy it out and reset */
		if (bits == 0) {
			*out_ptr++ = leftover[0];
			*out_ptr++ = leftover[1];
			*out_ptr++ = leftover[2];
			codes = 0;
			state_ptr->leftover_cnt = 0;
			offset = 0;
		}
	}
	/* If any residual bits, save them for the next call */
	if (bits > 0) {
		leftover[offset] = codes & 0xff;
		state_ptr->leftover_cnt += bits;
	}
	*out_size = (out_ptr - (unsigned char *)out_buf);
	return (AUDIO_SUCCESS);
}

/*
 * g723_decode()
 *
 * Description:
 *
 * Decodes a buffer of G.723 encoded data pointed to by 'in_buf' and
 * writes the resulting linear PCM, A-law or Mu-law words into a buffer
 * pointed to by 'out_buf'.
 *
 */
int
g723_decode(
	unsigned char	*in_buf,	/* Buffer of g723 encoded data. */
	int		data_size,	/* Size in bytes of in_buf. */
	Audio_hdr	*out_header,
	void		*out_buf,	/* Decoded data buffer. */
	int		*out_size,
	struct audio_g72x_state *state_ptr) /* the decoder's state structure. */
{
	unsigned char	*inbuf_end;
	unsigned char	*in_ptr, *out_ptr;
	short		*linear_ptr;
	unsigned int	codes;
	unsigned int	bits;
	int		cnt;

	short	sezi, sei, sez, se;		/* ACCUM */
	float	al;		/* use floating point for faster multiply */
	short	y, dif;				/* MIX */
	short	sr;				/* ADDB */
	char	pk0;				/* ADDC */
	short	dq;
	char	sigpk;
	short	dqsez;
	unsigned char i;

	in_ptr = in_buf;
	inbuf_end = in_buf + data_size;
	out_ptr = (unsigned char *)out_buf;
	linear_ptr = (short *)out_buf;

	/* Leftovers in decoding are only up to 8 bits */
	bits = state_ptr->leftover_cnt;
	codes = (bits > 0) ? state_ptr->leftover[0] : 0;

	while ((bits >= 3) || (in_ptr < (unsigned char *)inbuf_end)) {
		if (bits < 3) {
			codes += *in_ptr++ << bits;
			bits += 8;
		}

		/* ACCUM */
		sezi = _g723_fmult(state_ptr->b[0] >> 2, state_ptr->dq[0]);
		for (cnt = 1; cnt < 6; cnt++)
			sezi = sezi + _g723_fmult(state_ptr->b[cnt] >> 2,
			    state_ptr->dq[cnt]);
		sei = sezi;
		for (cnt = 1; cnt >= 0; cnt--)
			sei = sei + _g723_fmult(state_ptr->a[cnt] >> 2,
			    state_ptr->sr[cnt]);

		sez = sezi >> 1;
		se = sei >> 1;
		if (state_ptr->ap >= 256)
			y = state_ptr->yu;
		else {
			y = state_ptr->yl >> 6;
			dif = state_ptr->yu - y;
			al = state_ptr->ap >> 2;
			if (dif > 0)
				y += ((int)(dif * al)) >> 6;
			else if (dif < 0)
				y += ((int)(dif * al) + 0x3F) >> 6;
		}

		i = codes & 7;
		dq = _g723_reconstr(i, y);
		/* ADDB */
		if (dq < 0)
			sr = se - (dq & 0x3FFF);
		else
			sr = se + dq;


		dqsez = sr - se + sez;			/* ADDC */
		pk0 = (dqsez < 0) ? 1 : 0;
		sigpk = (dqsez) ? 0 : 1;

		_g723_update(y, i, dq, sr, pk0, state_ptr, sigpk);

		switch (out_header->encoding) {
		case AUDIO_ENCODING_LINEAR:
			*linear_ptr++ = ((sr <= -0x2000) ? -0x8000 :
			    (sr >= 0x1FFF) ? 0x7FFF : sr << 2);
			break;
		case AUDIO_ENCODING_ALAW:
			*out_ptr++ = _tandem_adjust_alaw(sr, se, y, i);
			break;
		case AUDIO_ENCODING_ULAW:
			*out_ptr++ = _tandem_adjust_ulaw(sr, se, y, i);
			break;
		default:
			return (AUDIO_ERR_ENCODING);
		}
		codes >>= 3;
		bits -= 3;
	}
	state_ptr->leftover_cnt = bits;
	if (bits > 0)
		state_ptr->leftover[0] = codes;

	/* Calculate number of samples returned */
	if (out_header->encoding == AUDIO_ENCODING_LINEAR)
		*out_size = linear_ptr - (short *)out_buf;
	else
		*out_size = out_ptr - (unsigned char *)out_buf;

	return (AUDIO_SUCCESS);
}
