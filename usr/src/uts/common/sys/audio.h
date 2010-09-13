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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_AUDIO_H
#define	_SYS_AUDIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/audioio.h>

#define	AUDIO_NAME		"audio support"	/* STREAMS module name */
#define	AUDIO_VERSION		"Rev 1"		/* 1st version of audio arch. */
#define	AUDIO_CONFIGURATION	"Config A"	/* 1st configuration */
#define	AUDIO_MOD_NAME		"Audio Device Support"
						/* STREAMS modldrv name */

#define	AUDIO_PLAY			0x0001		/* output */
#define	AUDIO_RECORD			0x0002		/* input */
#define	AUDIO_BOTH			(AUDIO_PLAY|AUDIO_RECORD)
#define	AUDIO_NO_SLEEP			0x0004
#define	AUDIO_SLEEP			0x0008


#define	AUDIO_INIT(I, S) {						\
		uint8_t *__x__;						\
		for (__x__ = (uint8_t *)(I);				\
			__x__ < (((uint8_t *)(I)) + (S));		\
				*__x__++ = (uint8_t)~0);		\
		}

/*
 * Audio support ioctls.
 */
#define	AIOC				('A'<<8)
#define	AUDIO_GET_CH_NUMBER		(AIOC|10)
#define	AUDIO_GET_CH_TYPE		(AIOC|11)
#define	AUDIO_GET_NUM_CHS		(AIOC|12)
#define	AUDIO_GET_AD_DEV		(AIOC|13)
#define	AUDIO_GET_APM_DEV		(AIOC|14)
#define	AUDIO_GET_AS_DEV		(AIOC|15)

/*
 * audio_device_type_e	- type of audio device the channel is associated with.
 */
enum audio_device_type {
	UNDEFINED = 0, AUDIO = 1, AUDIOCTL = 2, WTABLE = 3, MIDI = 4,
	ATIME = 5, USER1 = 9, USER2 = 10, USER3 = 11
};
typedef enum audio_device_type audio_device_type_e;

/*
 * audio_channel_t	- structure holds info on individual channels
 */
struct audio_channel {
	/*
	 * Process ID of the process that has this channel open. If this is
	 * set to 0 then the channel isn't owned by any process and is free.
	 */
	pid_t			pid;

	/*
	 * When a channel is opened it is a given a new minor number, we always
	 * clone the device. The ch_number is directly related to that new
	 * minor number. Each open gets a unique channel number.
	 */
	uint_t			ch_number;

	/*
	 * Type of audio device opened. This cloned channel retains that
	 * type, which determines which Audio Personality Module to use.
	 */
	audio_device_type_e	dev_type;

	/*
	 * Each device type has a state structure which describes the hardware.
	 * Because each state structure is different we need to know the size
	 * for apps to allocate the correct space.
	 */
	size_t			info_size;

	/*
	 * The device type's state structure.
	 */
	void			*info;
};
typedef struct audio_channel audio_channel_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AUDIO_H */
