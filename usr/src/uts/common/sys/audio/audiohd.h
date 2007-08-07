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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_AUDIOHD_H_
#define	_SYS_AUDIOHD_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/thread.h>
#include <sys/synch.h>
#include <sys/kstat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/audio.h>
#include <sys/audio/audio_support.h>
#include <sys/mixer.h>
#include <sys/audio/audio_mixer.h>


#define	AUDIOHD_SAMPR5510		5510
#define	AUDIOHD_SAMPR6620		6620
#define	AUDIOHD_SAMPR8000		8000
#define	AUDIOHD_SAMPR9600		9600
#define	AUDIOHD_SAMPR11025		11025
#define	AUDIOHD_SAMPR16000		16000
#define	AUDIOHD_SAMPR18900		18900
#define	AUDIOHD_SAMPR22050		22050
#define	AUDIOHD_SAMPR27420		27420
#define	AUDIOHD_SAMPR32000		32000
#define	AUDIOHD_SAMPR33075		33075
#define	AUDIOHD_SAMPR37800		37800
#define	AUDIOHD_SAMPR44100		44100
#define	AUDIOHD_SAMPR48000		48000

#define	AUDIOHD_SAMPLER_MAX	AUDIOHD_SAMPR48000
#define	AUDIOHD_MIN_INTS	32
#define	AUDIOHD_MAX_INTS	1500
#define	AUDIOHD_INTS	50
#define	AUDIOHD_MAX_PRECISION	AUDIO_PRECISION_16
#define	AUDIOHD_MAX_CHANNELS	AUDIO_CHANNELS_STEREO
#define	AUDIOHD_MAX_OUT_CHANNELS	32
#define	AUDIOHD_MAX_IN_CHANNELS		AUDIOHD_MAX_OUT_CHANNELS

#define	AUDIOHD_BSIZE		8192
#define	AUDIOHD_DEFAULT_SR	8000
#define	AUDIOHD_DEFAULT_CH	AUDIO_CHANNELS_MONO
#define	AUDIOHD_DEFAULT_PREC	AUDIO_PRECISION_8
#define	AUDIOHD_DEFAULT_ENC		AUDIO_ENCODING_ULAW
#define	AUDIOHD_DEFAULT_PGAIN	(AUDIO_MAX_GAIN * 3 / 4)
#define	AUDIOHD_DEFAULT_RGAIN	127
#define	AUDIOHD_DEFAULT_BAL			AUDIO_MID_BALANCE
#define	AUDIOHD_DEFAULT_MONITOR_GAIN		0

#define	AUDIOHD_DEV_NAME	"SUNW,audiohd"
#define	AUDIOHD_DEV_CONFIG	"onboard1"
#define	AUDIOHD_DEV_VERSION	"a"

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_AUDIOHD_H_ */
