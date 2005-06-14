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

#ifndef _MULTIMEDIA_AUDIO_ENCODE_H
#define	_MULTIMEDIA_AUDIO_ENCODE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <audio_types.h>
#include <audio_hdr.h>

/*
 * audio_encode.h
 *
 * u-law, A-law and linear PCM conversion tables and macros.
 */

/* PCM linear <-> a-law conversion tables */
extern short		_alaw2linear[];		/* 8-bit a-law to 16-bit PCM */
extern unsigned char	*_linear2alaw;		/* 13-bit PCM to 8-bit a-law */

/* PCM linear <-> u-law conversion tables */
extern short		_ulaw2linear[];		/* 8-bit u-law to 16-bit PCM */
extern unsigned char	*_linear2ulaw;		/* 14-bit PCM to 8-bit u-law */

/* A-law <-> u-law conversion tables */
extern unsigned char	_alaw2ulaw[];		/* 8-bit A-law to 8-bit u-law */
extern unsigned char	_ulaw2alaw[];		/* 8-bit u-law to 8-bit A-law */

/* PCM linear <-> a-law conversion macros */

/* a-law to 8,16,32-bit linear */
#define	audio_a2c(X)	((char)(_alaw2linear[(unsigned char) (X)] >> 8))
#define	audio_a2s(X)	(_alaw2linear[(unsigned char) (X)])
#define	audio_a2l(X)	(((long)_alaw2linear[(unsigned char) (X)]) << 16)

/* 8,16,32-bit linear to a-law */
#define	audio_c2a(X)	(_linear2alaw[((short)(X)) << 5])
#define	audio_s2a(X)	(_linear2alaw[((short)(X)) >> 3])
#define	audio_l2a(X)	(_linear2alaw[((long)(X)) >> 19])

/* PCM linear <-> u-law conversion macros */

/* u-law to 8,16,32-bit linear */
#define	audio_u2c(X)	((char)(_ulaw2linear[(unsigned char) (X)] >> 8))
#define	audio_u2s(X)	(_ulaw2linear[(unsigned char) (X)])
#define	audio_u2l(X)	(((long)_ulaw2linear[(unsigned char) (X)]) << 16)

/* 8,16,32-bit linear to u-law */
#define	audio_c2u(X)	(_linear2ulaw[((short)(X)) << 6])
#define	audio_s2u(X)	(_linear2ulaw[((short)(X)) >> 2])
#define	audio_l2u(X)	(_linear2ulaw[((long)(X)) >> 18])

/* A-law <-> u-law conversion macros */

#define	audio_a2u(X)	(_alaw2ulaw[(unsigned char)(X)])
#define	audio_u2a(X)	(_ulaw2alaw[(unsigned char)(X)])

/*
 * external declarations, type definitions and
 * macro definitions for use with the G.721 routines.
 */

/*
 * The following is the definition of the state structure
 * used by the G.721/G.723 encoder and decoder to preserve their internal
 * state between successive calls.  The meanings of the majority
 * of the state structure fields are explained in detail in the
 * CCITT Recommendation G.721.  The field names are essentially indentical
 * to variable names in the bit level description of the coding algorithm
 * included in this Recommendation.
 */
struct audio_g72x_state {
	long yl;	/* Locked or steady state step size multiplier. */
	short yu;	/* Unlocked or non-steady state step size multiplier. */
	short dms;	/* Short term energy estimate. */
	short dml;	/* Long term energy estimate. */
	short ap;	/* Linear weighting coefficient of 'yl' and 'yu'. */

	short a[2];	/* Coefficients of pole portion of prediction filter. */
	short b[6];	/* Coefficients of zero portion of prediction filter. */
	short pk[2];
			/*
			 * Signs of previous two samples of a partially
			 * reconstructed signal.
			 */
	short dq[6];
			/*
			 * Previous 6 samples of the quantized difference
			 * signal represented in an internal floating point
			 * format.
			 */
	short sr[2];
			/*
			 * Previous 2 samples of the quantized difference
			 * signal represented in an internal floating point
			 * format.
			 */
	char td;	/* delayed tone detect, new in 1988 version */
	unsigned char leftover[8];
			/*
			 * This array is used to store the last unpackable
			 * code bits in the event that the number of code bits
			 * which must be packed into a byte stream is not a
			 * multiple of the sample unit size.
			 */
	char leftover_cnt;
			/*
			 * Flag indicating the number of bits stored in
			 * 'leftover'.  Reset to 0 upon packing of 'leftover'.
			 */
};

/* External tables. */

/* Look-up table for performing fast log based 2. */
extern unsigned char _fmultanexp[];

/* Look-up table for perfoming fast 6bit by 6bit multiplication. */
extern unsigned char _fmultwanmant[];

/*
 * Look-up table for performing fast quantization of the step size
 * scale factor normalized log magnitude of the difference signal.
 */
extern unsigned char _quani[];

/* External function definitions. */

EXTERN_FUNCTION(void g721_init_state, (struct audio_g72x_state *state_ptr));
EXTERN_FUNCTION(int g721_encode, (
			void *in_buf,
			int data_size,
			Audio_hdr *in_header,
			unsigned char *out_buf,
			int *out_size,
			struct audio_g72x_state *state_ptr));
EXTERN_FUNCTION(int g721_decode, (
			unsigned char *in_buf,
			int data_size,
			Audio_hdr *out_header,
			void *out_buf,
			int *out_size,
			struct audio_g72x_state *state_ptr));

/*
 * Look-up table for performing fast quantization of the step size
 * scale factor normalized log magnitude of the difference signal.
 */
extern unsigned char _g723quani[];

/* External function definitions. */

EXTERN_FUNCTION(void g723_init_state, (struct audio_g72x_state *state_ptr));
EXTERN_FUNCTION(int g723_encode, (
			void *in_buf,
			int data_size,
			Audio_hdr *out_header,
			unsigned char *out_buf,
			int *out_size,
			struct audio_g72x_state *state_ptr));
EXTERN_FUNCTION(int g723_decode, (
			unsigned char *in_buf,
			int data_size,
			Audio_hdr *out_header,
			void *out_buf,
			int *out_size,
			struct audio_g72x_state *state_ptr));

#ifdef __cplusplus
}
#endif

#endif /* !_MULTIMEDIA_AUDIO_ENCODE_H */
