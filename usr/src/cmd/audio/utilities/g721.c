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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *
 * Description:
 *
 * g721_encode(), g721_decode(), g721_set_law()
 *
 * These routines comprise an implementation of the CCITT G.721 ADPCM coding
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
 * As outlined in the G.721 Recommendation, the algorithm is broken
 * down into modules.  Each section of code below is preceded by
 * the name of the module which it is implementing.
 *
 */
#include <stdlib.h>
#include <libaudio.h>

/*
 * Maps G.721 code word to reconstructed scale factor normalized log
 * magnitude values.
 */
static short	_dqlntab[16] = {-2048, 4, 135, 213, 273, 323, 373, 425,
		    425, 373, 323, 273, 213, 135, 4, -2048};

/* Maps G.721 code word to log of scale factor multiplier. */
static long	_witab[16] = {-384, 576, 1312, 2048, 3584, 6336, 11360, 35904,
		    35904, 11360, 6336, 3584, 2048, 1312, 576, -384};

/*
 * Maps G.721 code words to a set of values whose long and short
 * term averages are computed and then compared to give an indication
 * how stationary (steady state) the signal is.
 */
static short	_fitab[16] = {0, 0, 0, 0x200, 0x200, 0x200, 0x600, 0xE00,
		    0xE00, 0x600, 0x200, 0x200, 0x200, 0, 0, 0};

/*
 * g721_init_state()
 *
 * Description:
 *
 * This routine initializes and/or resets the audio_g72x_state structure
 * pointed to by 'state_ptr'.
 * All the initial state values are specified in the G.721 standard specs.
 */
void
g721_init_state(
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
 * _g721_fmult()
 *
 * returns the integer product of the "floating point" an and srn
 * by the lookup table _fmultwanmant[].
 *
 */
static int
_g721_fmult(
	int	an,
	int	srn)
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
 * _g721_update()
 *
 * updates the state variables for each output code
 *
 */
static void
_g721_update(
	int	y,
	int	i,
	int	dq,
	int	sr,
	int	pk0,
	struct audio_g72x_state *state_ptr,
	int	sigpk)
{
	int	cnt;
	long	fi;				/* FUNCTF */
	short	mag, exp;			/* FLOAT A */
	short	a2p;				/* LIMC */
	short	a1ul;				/* UPA1 */
	short	pks1, fa1;			/* UPA2 */
	char	tr;				/* tone/transition detector */
	short	thr2;

	mag = dq & 0x3FFF;
	/* TRANS */
	if (state_ptr->td == 0) {
		tr = 0;
	} else if (state_ptr->yl > 0x40000) {
		tr = (mag <= 0x2F80) ? 0 : 1;
	} else {
		thr2 = (0x20 + ((state_ptr->yl >> 10) & 0x1F)) <<
		    (state_ptr->yl >> 15);
		if (mag >= thr2) {
			tr = 1;
		} else {
			tr = (mag <= (thr2 - (thr2 >> 2))) ? 0 : 1;
		}
	}

	/*
	 * Quantizer scale factor adaptation.
	 */

	/* FUNCTW & FILTD & DELAY */
	state_ptr->yu = y + ((_witab[i] - y) >> 5);

	/* LIMB */
	if (state_ptr->yu < 544) {
		state_ptr->yu = 544;
	} else if (state_ptr->yu > 5120) {
		state_ptr->yu = 5120;
	}

	/* FILTE & DELAY */
	state_ptr->yl += state_ptr->yu + ((-state_ptr->yl) >> 6);

	/*
	 * Adaptive predictor.
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
			if (fa1 < -8191) {
				a2p -= 0x100;
			} else if (fa1 > 8191) {
				a2p += 0xFF;
			} else {
				a2p += fa1 >> 5;
			}

			if (pk0 ^ state_ptr->pk[1]) {
				/* LIMC */
				if (a2p <= -12160) {
					a2p = -12288;
				} else if (a2p >= 12416) {
					a2p = 12288;
				} else {
					a2p -= 0x80;
				}
			} else if (a2p <= -12416) {
				a2p = -12288;
			} else if (a2p >= 12160) {
				a2p = 12288;
			} else {
				a2p += 0x80;
			}
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
 * _g721_quantize()
 *
 * Description:
 *
 * Given a raw sample, 'd', of the difference signal and a
 * quantization step size scale factor, 'y', this routine returns the
 * G.721 codeword to which that sample gets quantized.  The step
 * size scale factor division operation is done in the log base 2 domain
 * as a subtraction.
 */
static unsigned int
_g721_quantize(
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
	char	i;	/* G.721 codeword. */

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
	i = _quani[dln & 0xFFF];
	if (d < 0)
		i ^= 0xF;	/* Stuff in sign of 'd'. */
	else if (i == 0)
		i = 0xF;	/* New in 1988 revision */

	return (i);
}

/*
 * _g721_reconstr()
 *
 * Description:
 *
 * Returns reconstructed difference signal 'dq' obtained from
 * G.721 codeword 'i' and quantization step size scale factor 'y'.
 * Multiplication is performed in log base 2 domain as addition.
 */
static unsigned long
_g721_reconstr(
	int		i,	/* G.721 codeword. */
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
	if (i & 8)
		dq -= 0x4000;

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
 * is adjusted by one level of A-law or u-law codes.
 *
 * Input:
 *	sr	decoder output linear PCM sample,
 *	se	predictor estimate sample,
 *	y	quantizer step size,
 *	i	decoder input code
 *
 * Return:
 *	adjusted A-law or u-law compressed sample.
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
	    (sr >= 0x1FFF)? 0x7FFF : sr << 2);	/* short to A-law compression */
	dx = (audio_a2s(sp) >> 2) - se; 	/* 16-bit prediction error */
	id = _g721_quantize(dx, y);

	if (id == i)			/* no adjustment on sp */
		return (sp);
	else {				/* sp adjustment needed */
		/* ADPCM codes : 8, 9, ... F, 0, 1, ... , 6, 7 */
		im = i ^ 8;		/* 2's complement to biased unsigned */
		imx = id ^ 8;

		if (imx > im) {		/* sp adjusted to next lower value */
			if (sp & 0x80)
				sd = (sp == 0xD5)? 0x55 :
				    ((sp ^ 0x55) - 1) ^ 0x55;
			else
				sd = (sp == 0x2A)? 0x2A :
				    ((sp ^ 0x55) + 1) ^ 0x55;
		} else {		/* sp adjusted to next higher value */
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
	int	sr,	/* decoder output linear PCM sample */
	int	se,	/* predictor estimate sample */
	int	y,	/* quantizer step size */
	int	i)	/* decoder input code */
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
	id = _g721_quantize(dx, y);
	if (id == i)
		return (sp);
	else {
		/* ADPCM codes : 8, 9, ... F, 0, 1, ... , 6, 7 */
		im = i ^ 8;		/* 2's complement to biased unsigned */
		imx = id ^ 8;
		if (imx > im) {		/* sp adjusted to next lower value */
			if (sp & 0x80)
				sd = (sp == 0xFF)? 0x7F : sp + 1;
			else
				sd = (sp == 0)? 0 : sp - 1;

		} else {		/* sp adjusted to next higher value */
			if (sp & 0x80)
				sd = (sp == 0x80)? 0x80 : sp - 1;
			else
				sd = (sp == 0x7F)? 0xFF : sp + 1;
		}
		return (sd);
	}
}

/*
 * g721_encode()
 *
 * Description:
 *
 * Encodes a buffer of linear PCM, A-law or u-law data pointed to by
 * 'in_buf' according * the G.721 encoding algorithm and packs the
 * resulting code words into bytes. The bytes of codeword pairs are
 * written to a buffer pointed to by 'out_buf'.
 *
 * Notes:
 *
 * In the event that the total number of codewords which have to be
 * written is odd, the last unpairable codeword is saved in the
 * state structure till the next call. It is then paired off and
 * packed with the first codeword of the new buffer. The number of
 * valid bytes in 'out_buf' is returned in *out_size. Note that
 * *out_size will not always be equal to half * of 'data_size' on input.
 * On the final call to 'g721_encode()' the calling program might want to
 * check if a codeword was left over. This can be
 * done by calling 'g721_encode()' with data_size = 0, which returns in
 * *out_size a 0 if nothing was leftover and 1 if a codeword was leftover
 * which now is in out_buf[0].
 *
 * The 4 lower significant bits of an individual byte in the output byte
 * stream is packed with a G.721 codeword first.  Then the 4 higher order
 * bits are packed with the next codeword.
 */
int
g721_encode(
	void		*in_buf,
	int		data_size,
	Audio_hdr	*in_header,
	unsigned char	*out_buf,
	int		*out_size,
	struct audio_g72x_state *state_ptr)
{
	short	sl;				/* EXPAND */
	short	sei, sezi, se, sez;		/* ACCUM */
	short	d;				/* SUBTA */
	float	al;		/* use floating point for faster multiply */
	short	y, dif;				/* MIX */
	short	sr;				/* ADDB */
	short	pk0, sigpk, dqsez;		/* ADDC */
	short	dq, i;
	int	cnt, cnta;
	int	out_leng;
	unsigned char *char_in;
	unsigned char *char_out;
	short	*short_ptr;

	if (data_size == 0) {
		/* Actually, the leftover count will never be more than 4 */
		for (i = 0; state_ptr->leftover_cnt > 0; i++) {
			*out_buf++ = state_ptr->leftover[i];
			state_ptr->leftover_cnt -= 8;
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
			data_size >>= 1;	/* divide to get sample cnt */
			short_ptr = (short *)in_buf;
		}
	} else {
		char_in = (unsigned char *)in_buf;
	}
	char_out = (unsigned char *)out_buf;
	if (state_ptr->leftover_cnt > 0) {
		*char_out = state_ptr->leftover[0];
		state_ptr->leftover_cnt = 0;
		data_size += 1;
		cnta = 1;
	} else {
		cnta = 0;
	}
	out_leng = (data_size & ~0x01);		/* clear low order bit */
	for (; cnta < data_size; cnta++) {
		/*  EXPAND  */
		switch (in_header->encoding) {
		case AUDIO_ENCODING_LINEAR:
			sl = *short_ptr++ >> 2;
			break;
		case AUDIO_ENCODING_ALAW:
			sl = audio_a2s(*char_in++) >> 2;
			break;
		case AUDIO_ENCODING_ULAW:
			sl = audio_u2s(*char_in++) >> 2; /* u-law to short */
			break;
		default:
			return (AUDIO_ERR_ENCODING);
		}

		/* ACCUM */
		sezi = _g721_fmult(state_ptr->b[0] >> 2, state_ptr->dq[0]);
		for (cnt = 1; cnt < 6; cnt++)
			sezi = sezi + _g721_fmult(state_ptr->b[cnt] >> 2,
			    state_ptr->dq[cnt]);
		sei = sezi;
		for (cnt = 1; cnt > -1; cnt--)
			sei = sei + _g721_fmult(state_ptr->a[cnt] >> 2,
			    state_ptr->sr[cnt]);
		sez = sezi >> 1;
		se = sei >> 1;
		d = sl - se;				/* SUBTA */

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

		i = _g721_quantize(d, y);
		dq = _g721_reconstr(i, y);
		/* ADDB */
		sr = (dq < 0) ? se - (dq & 0x3FFF) : se + dq;

		if (cnta & 1) {
			*char_out++ += i << 4;
		} else if (cnta < out_leng) {
			*char_out = i;
		} else {
			/*
			 * save the last codeword which can not be paired into
			 * a byte in the state stucture and set leftover_flag.
			 */
			state_ptr->leftover[0] = i;
			state_ptr->leftover_cnt = 4;
		}

		dqsez = sr + sez - se;		/* ADDC */
		if (dqsez == 0) {
			pk0 = 0;
			sigpk = 1;
		} else {
			pk0 = (dqsez < 0) ? 1 : 0;
			sigpk = 0;
		}

		_g721_update(y, i, dq, sr, pk0, state_ptr, sigpk);
	}
	*out_size = cnta >> 1;

	return (AUDIO_SUCCESS);
}

/*
 * g721_decode()
 *
 * Description:
 *
 * Decodes a buffer of G.721 encoded data pointed to by 'in_buf' and
 * writes the resulting linear PCM, A-law or Mu-law bytes into a buffer
 * pointed to by 'out_buf'.
 */
int
g721_decode(
	unsigned char	*in_buf,	/* Buffer of g721 encoded data. */
	int		data_size,	/* Size in bytes of in_buf. */
	Audio_hdr	*out_header,
	void		*out_buf,	/* Decoded data buffer. */
	int		*out_size,
	struct audio_g72x_state *state_ptr) /* the decoder's state structure. */
{
	short	sezi, sei, sez, se;		/* ACCUM */
	float	al;		/* use floating point for faster multiply */
	short	y, dif;				/* MIX */
	short sr;				/* ADDB */
	char	pk0, i;				/* ADDC */
	short	dq;
	char	sigpk;
	short	dqsez;
	unsigned char *char_in;
	unsigned char *char_out;
	int	cnt, cnta;
	short	*linear_out;

	*out_size = data_size << 1;
	char_in = (unsigned char *)in_buf;
	char_out = (unsigned char *)out_buf;
	linear_out = (short *)out_buf;
	for (cnta = 0; cnta < *out_size; cnta++) {
		if (cnta & 1)
			i = *char_in++ >> 4;
		else
			i = *char_in & 0xF;
		/* ACCUM */
		sezi = _g721_fmult(state_ptr->b[0] >> 2, state_ptr->dq[0]);
		for (cnt = 1; cnt < 6; cnt++)
			sezi = sezi + _g721_fmult(state_ptr->b[cnt] >> 2,
			    state_ptr->dq[cnt]);
		sei = sezi;
		for (cnt = 1; cnt >= 0; cnt--)
			sei = sei + _g721_fmult(state_ptr->a[cnt] >> 2,
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

		dq = _g721_reconstr(i, y);
		/* ADDB */
		if (dq < 0)
			sr = se - (dq & 0x3FFF);
		else
			sr = se + dq;

		switch (out_header->encoding) {
		case AUDIO_ENCODING_LINEAR:
			*linear_out++ = ((sr <= -0x2000) ? -0x8000 :
			    (sr >= 0x1FFF) ? 0x7FFF : sr << 2);
			break;
		case AUDIO_ENCODING_ALAW:
			*char_out++ = _tandem_adjust_alaw(sr, se, y, i);
			break;
		case AUDIO_ENCODING_ULAW:
			*char_out++ = _tandem_adjust_ulaw(sr, se, y, i);
			break;
		default:
			return (AUDIO_ERR_ENCODING);
		}
		/* ADDC */
		dqsez = sr - se + sez;
		pk0 = (dqsez < 0) ? 1 : 0;
		sigpk = (dqsez) ? 0 : 1;

		_g721_update(y, i, dq, sr, pk0, state_ptr, sigpk);
	}
	*out_size = cnta;

	return (AUDIO_SUCCESS);
}
