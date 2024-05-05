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

/*
 * This header file defines the .aiff audio file format.
 */

#ifndef _AIFF_H
#define	_AIFF_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Define the on-disk audio file header for the aiff file format.
 * By definition .aiff files are big endian. Macros are provided
 * to make the conversion easier.
 *
 * As many file formats, .aiff is composed of "chunks" of data grouped
 * together. The aiff specification states that chunks may be in any
 * order. Thus it is not possible to create a condensed header structure
 * as is possible with .aif or .wav.
 *
 * The first chunk is always a FORM chunk. All other chunks have the
 * following form:
 *
 *	Chunk ID
 *	Chunk Data Size
 *	Data
 *
 * AIFF files must have FORM, COMM, and SSND chunks. All other chunks
 * can be ignored. When a chunk with an unknown ID is found then the
 * application should read the next integer to get the size and then
 * seek past the unknown chunk to the next chunk.
 *
 * When building a .aiff header the size of the data isn't always known.
 * The following define is used for that situation.
 */
#define	AUDIO_AIFF_UNKNOWN_SIZE		(~0)

struct aiff_hdr_chunk {
	uint32_t	aiff_hdr_ID;		/* initial chunk ID */
	uint32_t	aiff_hdr_size;		/* file_size - aiff_hdr_chunk */
	uint32_t	aiff_hdr_data_type;	/* file data type */
};
typedef struct aiff_hdr_chunk aiff_hdr_chunk_t;

/* define for aiff_hdr_chunk.aiff_hdr_ID */
#define	AUDIO_AIFF_HDR_CHUNK_ID	((uint32_t)0x464f524d)	/* 'FORM' */

/* define for audio form type */
#define	AUDIO_AIFF_HDR_FORM_AIFF	((uint32_t)0x41494646)	/* 'AIFF' */

/*
 * The COMMon chunk definitions. Due to an unfortunate layout, the integer
 * aiff_comm_frames is not on a 4 byte boundary, which most compilers pad to
 * put back onto an integer boundary. Thus it is implemented as 4 chars which
 * gets around this. There are convenience macros to aid in getting and setting
 * the value. Also, some compilers will pad the end of the data structure to
 * place it on a 4 byte boundary, thus sizeof (aiff_comm_chunk_t) is off by
 * 2 bytes. Use AIFF_COMM_CHUNK_SIZE instead.
 */
#define	AUDIO_AIFF_COMM_SR_SIZE		10
#define	AUDIO_AIFF_COMM_CHUNK_SIZE	26

struct aiff_comm_chunk {
	uint32_t	aiff_comm_ID;		/* chunk ID */
	uint32_t	aiff_comm_size;		/* size without _ID and _size */
	uint16_t	aiff_comm_channels;	/* number of channels */
	uint8_t		aiff_comm_frames[4];	/* sample frames */
	int16_t		aiff_comm_sample_size;	/* bits in each sample */
	uint8_t		aiff_comm_sample_rate[AUDIO_AIFF_COMM_SR_SIZE];
						/* SR in float */
};
typedef struct aiff_comm_chunk aiff_comm_chunk_t;

/* define for aiff_comm_chunk.aiff_comm_ID */
#define	AUDIO_AIFF_COMM_ID		((uint32_t)0x434f4d4d)	/* 'COMM' */

/* define for aiff_comm_chunk.aiff_comm_size */
#define	AUDIO_AIFF_COMM_SIZE		18

/* define for aiff_comm_chunk.aiff_comm_channels */
#define	AUDIO_AIFF_COMM_CHANNELS_MONO		1
#define	AUDIO_AIFF_COMM_CHANNELS_STEREO		2

/* defines to get and set the frame count */
#define	AUDIO_AIFF_COMM_FRAMES2INT(X)					\
	(((X)[0] << 24) | ((X)[1] << 16) | ((X)[2] << 8) | (X)[3])
#define	AUDIO_AIFF_COMM_INT2FRAMES(X, D)				\
	(X)[0] = (D) >> 24; (X)[1] = (D) >> 16; (X)[2] = (D) >> 8; (X)[3] = (D);

/* define for aiff_comm_chunk.aiff_comm_sample_size */
#define	AUDIO_AIFF_COMM_8_BIT_SAMPLE_SIZE	8
#define	AUDIO_AIFF_COMM_16_BIT_SAMPLE_SIZE	16


/*
 * The SSND chunk definitions. Sound data immediately follows this data
 * structure. Use aiff_ssnd_block_size to move past the data. The size of
 * audio is aiff_ssnd_size - 8.
 */
struct aiff_ssnd_chunk {
	uint32_t	aiff_ssnd_ID;		/* chunk ID */
	uint32_t	aiff_ssnd_size;		/* size without _id and _size */
	uint32_t	aiff_ssnd_offset;	/* offset to frame beginning */
	uint32_t	aiff_ssnd_block_size;	/* block size */
};
typedef struct aiff_ssnd_chunk aiff_ssnd_chunk_t;

/* define for aiff_ssnd_chunk.aiff_ssnd_ID */
#define	AUDIO_AIFF_SSND_ID		((uint32_t)0x53534e44)	/* 'SSND' */

/* byte swapping macros */
#if defined(__BIG_ENDIAN)
#define	AUDIO_AIFF_FILE2HOST_INT(from, to)				\
		*((int *)(to)) = *((int *)(from))
#define	AUDIO_AIFF_FILE2HOST_SHORT(from, to)				\
		*((short *)(to)) = *((short *)(from))
#define	AUDIO_AIFF_HOST2FILE_INT(from, to)				\
		*((int *)(to)) = *((int *)(from))
#define	AUDIO_AIFF_HOST2FILE_SHORT(from, to)				\
		*((short *)(to)) = *((short *)(from))
#elif defined(_LITTLE_ENDIAN)
#define	AUDIO_AIFF_FILE2HOST_INT(from, to)				\
		(*to) = ((((*from) >> 24) & 0xff) | (((*from) & 0xff) << 24) | \
		(((*from) >> 8) & 0xff00) | (((*from) & 0xff00) << 8))
#define	AUDIO_AIFF_FILE2HOST_SHORT(from, to)				\
		(*to) = ((((*from) >> 8) & 0xff) | (((*from) & 0xff) << 8))
#define	AUDIO_AIFF_HOST2FILE_INT(from, to)				\
		AUDIO_AIFF_FILE2HOST_INT((from), (to))
#define	AUDIO_AIFF_HOST2FILE_SHORT(from, to)				\
		AUDIO_AIFF_FILE2HOST_SHORT((from), (to))
#else
#error unknown machine type;
#endif	/* byte swapping */


#ifdef	__cplusplus
}
#endif

#endif /* _AIFF_H */
