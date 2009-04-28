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

#ifndef	_SYS_AUDIO_AUDIO_COMMON_H
#define	_SYS_AUDIO_AUDIO_COMMON_H

#include <sys/mkdev.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

/* Shared data structures */
typedef struct audio_parms audio_parms_t;
typedef struct audio_buffer audio_buffer_t;
typedef struct audio_stream audio_stream_t;
typedef struct audio_engine audio_engine_t;
typedef struct audio_client audio_client_t;
typedef struct audio_dev audio_dev_t;
typedef struct audio_mixer_ops audio_mixer_ops_t;
typedef struct audio_engine_ops audio_engine_ops_t;
typedef struct audio_ctrl audio_ctrl_t;
typedef struct audio_ctrl_desc audio_ctrl_desc_t;

struct audio_ctrl_desc {
	const char		*acd_name;		/* Controls Mnemonic */
	uint32_t		acd_type;		/* Entry type */
	uint64_t		acd_flags;		/* Characteristics */
	/*
	 * Minimum and Maximum values for this control.  The value
	 * must be between these values inclusive.  For
	 * AUDIO_CTRL_TYPE_ENUM, the maxvalue is a bitmask of
	 * supported controls.
	 */
	uint64_t		acd_maxvalue;		/* max value control */
	uint64_t		acd_minvalue;		/* min value control */
	/*
	 * Array of pointers to names for each enum position. This
	 * should be null for all but AUDIO_CTRL_TYPE_ENUM.
	 */
	const char		*acd_enum[64];
};

/*
 * Audio data formats.  Note that these are represented int a bit
 * field, to allow for multiple values to be represented in the same
 * integer (in certain portions of the API.)
 */
#define	AUDIO_FORMAT_NONE		0x00000000U
#define	AUDIO_FORMAT_ULAW		0x00000001U
#define	AUDIO_FORMAT_ALAW		0x00000002U
#define	AUDIO_FORMAT_S8			0x00000004U
#define	AUDIO_FORMAT_U8			0x00000008U
#define	AUDIO_FORMAT_S16_LE		0x00000010U
#define	AUDIO_FORMAT_S16_BE		0x00000020U
#define	AUDIO_FORMAT_U16_LE		0x00000040U
#define	AUDIO_FORMAT_U16_BE		0x00000080U
#define	AUDIO_FORMAT_S24_LE		0x00000100U
#define	AUDIO_FORMAT_S24_BE		0x00000200U
#define	AUDIO_FORMAT_S32_LE		0x00000400U
#define	AUDIO_FORMAT_S32_BE		0x00000800U
#define	AUDIO_FORMAT_S24_PACKED		0x00001000U
#define	AUDIO_FORMAT_AC3		0x00010000U
#define	AUDIO_FORMAT_OPAQUE_MASK	0xffff0000U
#define	AUDIO_FORMAT_CONVERTIBLE	0x0000ffffU
/*
 * We only support signed 16, 24, and 32 bit format conversions in the
 * engines, for simplicity.  (We haven't run into any engines that
 * require other formats.)
 */
#define	AUDIO_FORMAT_PCM		0x00000f30

/*
 * Some big endian/little endian handling macros (native endian and opposite
 * endian formats). The usage of these macros is described in the OSS
 * Programmer's Manual.
 */

#if defined(_BIG_ENDIAN)

#define	AUDIO_FORMAT_S16_NE	AUDIO_FORMAT_S16_BE
#define	AUDIO_FORMAT_U16_NE	AUDIO_FORMAT_U16_BE
#define	AUDIO_FORMAT_S32_NE	AUDIO_FORMAT_S32_BE
#define	AUDIO_FORMAT_S24_NE	AUDIO_FORMAT_S24_BE
#define	AUDIO_FORMAT_S16_OE	AUDIO_FORMAT_S16_LE
#define	AUDIO_FORMAT_U16_OE	AUDIO_FORMAT_U16_LE
#define	AUDIO_FORMAT_S32_OE	AUDIO_FORMAT_S32_LE
#define	AUDIO_FORMAT_S24_OE	AUDIO_FORMAT_S24_LE

#elif defined(_LITTLE_ENDIAN)
#define	AUDIO_FORMAT_S16_NE	AUDIO_FORMAT_S16_LE
#define	AUDIO_FORMAT_U16_NE	AUDIO_FORMAT_U16_LE
#define	AUDIO_FORMAT_S32_NE	AUDIO_FORMAT_S32_LE
#define	AUDIO_FORMAT_S24_NE	AUDIO_FORMAT_S24_LE
#define	AUDIO_FORMAT_S16_OE	AUDIO_FORMAT_S16_BE
#define	AUDIO_FORMAT_U16_OE	AUDIO_FORMAT_U16_BE
#define	AUDIO_FORMAT_S32_OE	AUDIO_FORMAT_S32_BE
#define	AUDIO_FORMAT_S24_OE	AUDIO_FORMAT_S24_BE

#else
#error "Machine endianness undefined"
#endif

/*
 * These are parameterized around the maximum minor number available
 * for use in the filesystem.  Unfortunately, we have to use 32-bit limits,
 * because we could have 32-bit userland apps (we usually will, in fact).
 */
#define	AUDIO_MN_CLONE_NBITS	(NBITSMINOR32 - 1)
#define	AUDIO_MN_CLONE_MASK	(1U << (AUDIO_MN_CLONE_NBITS - 1))
#define	AUDIO_MN_TYPE_NBITS	(4)
#define	AUDIO_MN_TYPE_SHIFT	(0)
#define	AUDIO_MN_TYPE_MASK	((1U << AUDIO_MN_TYPE_NBITS) - 1)
#define	AUDIO_MN_INST_NBITS	((NBITSMINOR32 - 1) - AUDIO_MN_TYPE_NBITS)
#define	AUDIO_MN_INST_MASK	((1U << AUDIO_MN_INST_NBITS) - 1)
#define	AUDIO_MN_INST_SHIFT	(AUDIO_MN_TYPE_NBITS)
#define	AUDIO_MKMN(inst, typ)	\
	(((inst) << AUDIO_MN_INST_SHIFT) | ((typ) << AUDIO_MN_TYPE_SHIFT))

#define	AUDIO_MINOR_MIXER	(0)
#define	AUDIO_MINOR_DSP		(1)
/* 2 is reserved for now */
#define	AUDIO_MINOR_DEVAUDIO	(3)
#define	AUDIO_MINOR_DEVAUDIOCTL	(4)
#define	AUDIO_MINOR_SNDSTAT	(AUDIO_MN_TYPE_MASK)

/* reserved minors for driver specific use */
#define	AUDIO_MINOR_DRV1	(AUDIO_MINOR_SNDSTAT - 1)
#define	AUDIO_MINOR_DRV2	(AUDIO_MINOR_SNDSTAT - 2)


/* Various controls */
#define	AUDIO_CTRL_ID_VOLUME	"volume"
#define	AUDIO_CTRL_ID_LINEOUT	"line-out"
#define	AUDIO_CTRL_ID_FRONT	"front"
#define	AUDIO_CTRL_ID_REAR	"rear"
#define	AUDIO_CTRL_ID_HEADPHONE	"headphones"
#define	AUDIO_CTRL_ID_CENTER	"center"
#define	AUDIO_CTRL_ID_LFE	"lfe"
#define	AUDIO_CTRL_ID_SURROUND	"surround"
#define	AUDIO_CTRL_ID_SPEAKER	"speaker"
#define	AUDIO_CTRL_ID_AUX1OUT	"aux1-out"
#define	AUDIO_CTRL_ID_AUX2OUT	"aux2-out"
#define	AUDIO_CTRL_ID_BASS	"bass"
#define	AUDIO_CTRL_ID_TREBLE	"treble"
#define	AUDIO_CTRL_ID_3DDEPTH	"3d-depth"
#define	AUDIO_CTRL_ID_3DCENT	"3d-center"
#define	AUDIO_CTRL_ID_3DENHANCE	"3d-enhance"
#define	AUDIO_CTRL_ID_PHONE	"phone"
#define	AUDIO_CTRL_ID_MIC	"mic"
#define	AUDIO_CTRL_ID_LINEIN	"line-in"
#define	AUDIO_CTRL_ID_CD	"cd"
#define	AUDIO_CTRL_ID_VIDEO	"video"
#define	AUDIO_CTRL_ID_AUX1IN	"aux1-in"
#define	AUDIO_CTRL_ID_PCMIN	"pcm"
#define	AUDIO_CTRL_ID_RECGAIN	"record-gain"
#define	AUDIO_CTRL_ID_AUX2IN	"aux2-in"
#define	AUDIO_CTRL_ID_MICBOOST	"micboost"
#define	AUDIO_CTRL_ID_LOOPBACK	"loopback"
#define	AUDIO_CTRL_ID_LOUDNESS	"loudness"
#define	AUDIO_CTRL_ID_OUTPUTS	"outputs"
#define	AUDIO_CTRL_ID_INPUTS	"inputs"
#define	AUDIO_CTRL_ID_RECSRC	"record-source"
#define	AUDIO_CTRL_ID_MONSRC	"monitor-source"
#define	AUDIO_CTRL_ID_DIAG	"diag"
#define	AUDIO_CTRL_ID_BEEP	"beep"
#define	AUDIO_CTRL_ID_MONGAIN	"monitor-gain"
#define	AUDIO_CTRL_ID_STEREOSIM	"stereo-simulate"	/* AC'97 feature */
#define	AUDIO_CTRL_ID_MICGAIN	"mic-gain"		/* mono mic gain */
#define	AUDIO_CTRL_ID_SPKSRC	"speaker-source"	/* AC'97 feature */
#define	AUDIO_CTRL_ID_MICSRC	"mic-source"		/* AC'97 feature */
#define	AUDIO_CTRL_ID_JACK1	"jack1"			/* jack repurposing */
#define	AUDIO_CTRL_ID_JACK2	"jack2"
#define	AUDIO_CTRL_ID_JACK3	"jack3"
#define	AUDIO_CTRL_ID_JACK4	"jack4"
#define	AUDIO_CTRL_ID_JACK5	"jack5"
#define	AUDIO_CTRL_ID_JACK6	"jack6"
#define	AUDIO_CTRL_ID_JACK7	"jack7"
#define	AUDIO_CTRL_ID_DOWNMIX	"downmix"
#define	AUDIO_CTRL_ID_SPREAD	"spread"

/*
 * Names for ports.
 */
#define	AUDIO_PORT_MIC			"mic"
#define	AUDIO_PORT_CD			"cd"
#define	AUDIO_PORT_VIDEO		"video"
#define	AUDIO_PORT_AUX1OUT		"aux1-out"
#define	AUDIO_PORT_AUX2OUT		"aux2-out"
#define	AUDIO_PORT_LINEOUT		"line-out"
#define	AUDIO_PORT_STEREOMIX		"stereo-mix"
#define	AUDIO_PORT_MONOMIX		"mono-mix"
#define	AUDIO_PORT_PHONE		"phone"
#define	AUDIO_PORT_REAR			"rear"
#define	AUDIO_PORT_CENTER		"center"
#define	AUDIO_PORT_SURROUND		"surround"
#define	AUDIO_PORT_LFE			"lfe"
#define	AUDIO_PORT_SPEAKER		"speaker"
#define	AUDIO_PORT_LINEIN		"line-in"
#define	AUDIO_PORT_AUX1IN		"aux1-in"
#define	AUDIO_PORT_AUX2IN		"aux2-in"
#define	AUDIO_PORT_HEADPHONES		"headphones"
#define	AUDIO_PORT_SPDIFIN		"spdif-in"
#define	AUDIO_PORT_SPDIFOUT		"spdif-out"
#define	AUDIO_PORT_CENLFE		"center/lfe"	/* combined jack use */
#define	AUDIO_PORT_MIC1			"mic1"
#define	AUDIO_PORT_MIC2			"mic2"
#define	AUDIO_PORT_DIGOUT		"digital-out"
#define	AUDIO_PORT_DIGIN		"digital-in"
#define	AUDIO_PORT_HDMI			"hdmi"
#define	AUDIO_PORT_MODEM		"modem"
#define	AUDIO_PORT_HANDSET		"handset"
#define	AUDIO_PORT_OTHER		"other"
#define	AUDIO_PORT_STEREO		"stereo"	/* e.g. mic array */
#define	AUDIO_PORT_NONE			"none"

/*
 * A few common values that sometimes we see.
 */
#define	AUDIO_VALUE_ON			"on"
#define	AUDIO_VALUE_OFF			"off"
#define	AUDIO_VALUE_VERYLOW		"very-low"
#define	AUDIO_VALUE_LOW			"low"
#define	AUDIO_VALUE_MEDIUM		"medium"
#define	AUDIO_VALUE_HIGH		"high"
#define	AUDIO_VALUE_VERYHIGH		"very-high"

/*
 * Posible return values for walk callback function
 */
#define	AUDIO_WALK_CONTINUE	1	/* continue walk */
#define	AUDIO_WALK_STOP		2	/* stop the walk */
#define	AUDIO_WALK_RESTART	3	/* restart the walk from beginning */

/*
 * Control types
 */
#define	AUDIO_CTRL_TYPE_BOOLEAN		1	/* ON/OFF control */
#define	AUDIO_CTRL_TYPE_ENUM		2	/* Enumerated list */
#define	AUDIO_CTRL_TYPE_STEREO		3	/* stereo level control */
#define	AUDIO_CTRL_TYPE_MONO		4	/* mono level control */
#define	AUDIO_CTRL_TYPE_METER		5	/* VU meter */

/*
 * Control characteristics flags
 */
#define	AUDIO_CTRL_FLAG_READABLE	0x00000001	/* Control readable */
#define	AUDIO_CTRL_FLAG_WRITEABLE	0x00000002	/* Control writable */
#define	AUDIO_CTRL_FLAG_RW		0x00000003	/* Read/writeable */
#define	AUDIO_CTRL_FLAG_VUPEAK		0x00000004	/* peak meter */
#define	AUDIO_CTRL_FLAG_CENTIBEL	0x00000008	/* Centibel (0.1 dB) */
#define	AUDIO_CTRL_FLAG_DECIBEL		0x00000010	/* Step size of 1 dB */
#define	AUDIO_CTRL_FLAG_POLL		0x00000020	/* May change itself */
#define	AUDIO_CTRL_FLAG_MAINVOL		0x00000100	/* Main volume ctrl */
#define	AUDIO_CTRL_FLAG_PCMVOL		0x00000200	/* PCM output volume */
#define	AUDIO_CTRL_FLAG_RECVOL		0x00000400	/* PCM record volume */
#define	AUDIO_CTRL_FLAG_MONVOL		0x00000800	/* Monitor volume */
#define	AUDIO_CTRL_FLAG_PLAY		0x00001000	/* Playback control */
#define	AUDIO_CTRL_FLAG_REC		0x00002000	/* Record control */
#define	AUDIO_CTRL_FLAG_3D		0x00004000	/* 3D effect control */
#define	AUDIO_CTRL_FLAG_TONE		0x00008000	/* Tone control */
#define	AUDIO_CTRL_FLAG_MONITOR		0x00010000	/* Monitor control */
#define	AUDIO_CTRL_FLAG_DIGITAL		0x00020000	/* Digital control */

/*
 * AUDIO_CTRL_TYPE_ENUM might allow more than a single value to be
 * selected.  (Value is a bitmask.)
 */
#define	AUDIO_CTRL_FLAG_MULTI		0x00000040

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AUDIO_AUDIO_COMMON_H */
