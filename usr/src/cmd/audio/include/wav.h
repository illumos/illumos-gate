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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This header file defines the .wav audio file format.
 */

#ifndef _WAV_H
#define	_WAV_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Define the on-disk audio file header for the .wav file format.
 * By definition .wav files are little endian. Macros are provided
 * to make the conversion easier.
 *
 * The .wav format is one of the variations of the RIFF format. To
 * that end it contains a RIFF header chunk, a type chunk, a format
 * chunk, and then one or more data chunks. The following illustrates
 * the format:
 *
 *	RIFF	<Length of data>		RIFF header chunk
 *	WAVE					type chunk
 *	fmt<sp>					format chunk
 *	DATA	<Length of data> <data>		data chunk (one or more)
 *
 * Since the RIFF headers never change for a .wav file there's no real reason
 * to separate the header into the different chunks. Thus a single header
 * structure is defined for the header.
 *
 * When building a .wav header the size of the data isn't always known.
 * The following define is used for that situation.
 */
#define	AUDIO_WAV_UNKNOWN_SIZE		(~0)

struct wav_filehdr {
	uint32_t	wav_riff_ID;		/* RIFF file ID */
	int32_t		wav_riff_size;		/* size of file - wav_riff* */
	uint32_t	wav_type_ID;		/* file type ID */
	uint32_t	wav_fmt_ID;		/* format ID */
	uint32_t	wav_fmt_size;		/* size of wav_fmt_*'s */
	uint16_t	wav_fmt_encoding;	/* audio data encoding method */
	uint16_t	wav_fmt_channels;	/* number of channels */
	uint32_t	wav_fmt_sample_rate;	/* sample rate */
	uint32_t	wav_fmt_bytes_per_second; /* bytes per sec. of audio */
	uint16_t	wav_fmt_bytes_per_sample; /* bytes per audio sample */
	uint16_t	wav_fmt_bits_per_sample; /* bits per audio sample */
	uint32_t	wav_data_ID;		/* data ID */
	int32_t		wav_data_size;		/* size of the data */
};
typedef struct wav_filehdr wav_filehdr_t;

/* define for wav_filehdr.wav_riff_ID */
#define	AUDIO_WAV_RIFF_ID		((uint32_t)0x46464952)	/* 'RIFF' */

/* define for wav_filehdr.wav_wave_ID */
#define	AUDIO_WAV_TYPE_ID		((uint32_t)0x45564157)	/* 'WAVE' */

/* define for wav_filehdr.wav_fmt_ID */
#define	AUDIO_WAV_FORMAT_ID		((uint32_t)0x20746d66)	/* 'fmt ' */

/* define for wav_filehdr.wav_fmt_size */
#define	AUDIO_WAV_FORMAT_SIZE			0x10	/* constant value */

/* defines for wav_filehdr.wav_fmt_encoding */
#define	AUDIO_WAV_FMT_ENCODING_UNKNOWN			0x0000
#define	AUDIO_WAV_FMT_ENCODING_PCM			0x0001
#define	AUDIO_WAV_FMT_ENCODING_MS_ADPCM			0x0002
#define	AUDIO_WAV_FMT_ENCODING_ALAW			0x0006
#define	AUDIO_WAV_FMT_ENCODING_MULAW			0x0007
#define	AUDIO_WAV_FMT_ENCODING_DVI_ADPCM		0x0011

/* defines for wav_filehdr.wav_fmt_channels */
#define	AUDIO_WAV_FMT_CHANNELS_MONO			0
#define	AUDIO_WAV_FMT_CHANNELS_STEREO			1

/* defines for wav_filehdr.wav_fmt_bytes_per_sample */
#define	AUDIO_WAV_FMT_BYTES_PER_SAMPLE_8_BIT_MONO	1
#define	AUDIO_WAV_FMT_BYTES_PER_SAMPLE_8_BIT_STEREO	2
#define	AUDIO_WAV_FMT_BYTES_PER_SAMPLE_16_BIT_MONO	2
#define	AUDIO_WAV_FMT_BYTES_PER_SAMPLE_16_BIT_STEREO	4

/* defines for wav_filehdr.wav_fmt_bits_per_sample */
#define	AUDIO_WAV_FMT_BITS_PER_SAMPLE_8_BITS		8
#define	AUDIO_WAV_FMT_BITS_PER_SAMPLE_16_BITS		16

/* defines for wav_filehdr.wav_data_ID */
#define	AUDIO_WAV_DATA_ID_UC		((uint32_t)0x41544144)	/* DATA */
#define	AUDIO_WAV_DATA_ID_LC		((uint32_t)0x61746164)	/* data */


/* byte swapping macros */
#if defined(_BIG_ENDIAN)				/* big endian */
#define	AUDIO_WAV_FILE2HOST_INT(from, to)				\
		(*to) = ((((*from) >> 24) & 0xff) | (((*from) & 0xff) << 24) | \
		(((*from) >> 8) & 0xff00) | (((*from) & 0xff00) << 8))
#define	AUDIO_WAV_FILE2HOST_SHORT(from, to)				\
		(*to) = ((((*from) >> 8) & 0xff) | (((*from) & 0xff) << 8))
#define	AUDIO_WAV_HOST2FILE_INT(from, to)				\
		AUDIO_WAV_FILE2HOST_INT((from), (to))
#define	AUDIO_WAV_HOST2FILE_SHORT(from, to)				\
		AUDIO_WAV_FILE2HOST_SHORT((from), (to))

#elif defined(_LITTLE_ENDIAN)				/* little endian */
#define	AUDIO_WAV_FILE2HOST_INT(from, to)				\
		*((int *)(to)) = *((int *)(from))
#define	AUDIO_WAV_FILE2HOST_SHORT(from, to)				\
		*((short *)(to)) = *((short *)(from))
#define	AUDIO_WAV_HOST2FILE_INT(from, to)				\
		*((int *)(to)) = *((int *)(from))
#define	AUDIO_WAV_HOST2FILE_SHORT(from, to)				\
		*((short *)(to)) = *((short *)(from))

#else
#error unknown machine type;
#endif	/* byte swapping */


#ifdef	__cplusplus
}
#endif

#endif /* _WAV_H */
