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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _AUDIO_AU_H
#define	_AUDIO_AU_H

#include <sys/isa_defs.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Define an on-disk audio file header for the AU file format.
 *
 * Note that there is an optional 'info' field that immediately follows this
 * structure in the file. It is an optional length field that is sometimes
 * used to store additional information. At the minimum, it is at
 * least 4 bytes.
 *
 * The offset field is problematic in the general case because the
 * field is really "data location", which does not ensure that all
 * the bytes between the header and the data are really 'info'.
 * Further, there are no absolute guarantees that the info is ASCII text.
 *
 * When audio files are passed through pipes, the au_data_size field may
 * not be known in advance.  In such cases, au_data_size should be
 * set to AUDIO_AU_UNKNOWN_SIZE.
 */

struct au_filehdr {
	uint32_t	au_magic;	/* magic number */
	uint32_t	au_offset;	/* size of this header */
	uint32_t	au_data_size;	/* length of data */
	uint32_t	au_encoding;	/* data encoding format */
	uint32_t	au_sample_rate;	/* samples per second */
	uint32_t	au_channels;	/* number of interleaved channels */
};
typedef struct au_filehdr au_filehdr_t;

	/*
	 *	This is the appearance of a typical AU audio file as described
	 *	by this structure.
	 *
	 *	------------------------------------------------------------
	 *	|			|		|		   |
	 *	|   AU Audio Header	|    Info	|   Audio Data	   |
	 *	|			| (optional)	|		   |
	 *	|			|		|		   |
	 *	|	24 bytes	| 4 bytes (min)	|    n bytes	   |
	 *	|			|		|		   |
	 *	------------------------------------------------------------
	 */

/* Define the magic number */
#define	AUDIO_AU_FILE_MAGIC	((uint32_t)0x2e736e64)	/* ".snd" */

/* Unknown header size */
#define	AUDIO_AU_UNKNOWN_SIZE	((unsigned)(~0))	/* (unsigned) -1 */

/* Define the AU encoding fields */
#define	AUDIO_AU_ENCODING_ULAW		(1)	/* 8-bit u-law */
#define	AUDIO_AU_ENCODING_LINEAR_8	(2)	/* 8-bit linear PCM */
#define	AUDIO_AU_ENCODING_LINEAR_16	(3)	/* 16-bit linear PCM */
#define	AUDIO_AU_ENCODING_LINEAR_24	(4)	/* 24-bit linear PCM */
#define	AUDIO_AU_ENCODING_LINEAR_32	(5)	/* 32-bit linear PCM */
#define	AUDIO_AU_ENCODING_FLOAT		(6)	/* 32-bit IEEE floating point */
#define	AUDIO_AU_ENCODING_DOUBLE	(7)	/* 64-bit IEEE double */
						/*   precision float */
#define	AUDIO_AU_ENCODING_FRAGMENTED	(8)	/* Fragmented sample data */
#define	AUDIO_AU_ENCODING_DSP		(10)	/* DSP program */
#define	AUDIO_AU_ENCODING_FIXED_8	(11)	/* 8-bit fixed point */
#define	AUDIO_AU_ENCODING_FIXED_16	(12)	/* 16-bit fixed point */
#define	AUDIO_AU_ENCODING_FIXED_24	(13)	/* 24-bit fixed point */
#define	AUDIO_AU_ENCODING_FIXED_32	(14)	/* 32-bit fixed point */
#define	AUDIO_AU_ENCODING_EMPHASIS	(18)	/* 16-bit linear with */
						/*   emphasis */
#define	AUDIO_AU_ENCODING_COMPRESSED	(19)	/* 16-bit linear compressed */
#define	AUDIO_AU_ENCODING_EMP_COMP	(20)	/* 16-bit linear with */
						/*   emphasis and compression */
#define	AUDIO_AU_ENCODING_MUSIC_KIT	(21)	/* Music kit DSP commands */
#define	AUDIO_AU_ENCODING_ADPCM_G721	(23)	/* 4-bit CCITT G.721 ADPCM */
#define	AUDIO_AU_ENCODING_ADPCM_G722	(24)	/* CCITT G.722 ADPCM */
#define	AUDIO_AU_ENCODING_ADPCM_G723_3	(25)	/* CCITT G.723.3 ADPCM */
#define	AUDIO_AU_ENCODING_ADPCM_G723_5	(26)	/* CCITT G.723.5 ADPCM */
#define	AUDIO_AU_ENCODING_ALAW		(27)	/* 8-bit A-law G.711 */


/* Byte swapping routines */
#if defined(_BIG_ENDIAN)
#define	AUDIO_AU_FILE2HOST(from, to)	*((long *)(to)) = *((long *)(from))
#else
#define	AUDIO_AU_FILE2HOST(from, to)					\
			    ((char *)(to))[0] = ((char *)(from))[3];	\
			    ((char *)(to))[1] = ((char *)(from))[2];	\
			    ((char *)(to))[2] = ((char *)(from))[1];	\
			    ((char *)(to))[3] = ((char *)(from))[0];
#endif /* byte swapping */

#if defined(__sparc) || defined(__i386) || defined(__amd64)
#define	AUDIO_AU_HOST2FILE(from, to)	AUDIO_AU_FILE2HOST((from), (to))
#else
#error unknown machine type;
#endif /* encode */

#ifdef	__cplusplus
}
#endif

#endif /* _AUDIO_AU_H */
