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

#ifndef	_SYS_AUDIO810_H_
#define	_SYS_AUDIO810_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Header file for the audio810 device driver
 */

/*
 * Values returned by the AUDIO_GETDEV ioctl()
 */
#define	I810_DEV_NAME			"SUNW,audio810"
#define	I810_DEV_CONFIG			"onboard1"
#define	I810_DEV_VERSION		"a"

/*
 * Driver supported configuration information
 */
#define	I810_NAME			"audio810"
#define	I810_MOD_NAME			"mixer audio driver"

#define	I810_SAMPR5510			(5510)
#define	I810_SAMPR6620			(6620)
#define	I810_SAMPR8000			(8000)
#define	I810_SAMPR9600			(9600)
#define	I810_SAMPR11025			(11025)
#define	I810_SAMPR16000			(16000)
#define	I810_SAMPR18900			(18900)
#define	I810_SAMPR22050			(22050)
#define	I810_SAMPR27420			(27420)
#define	I810_SAMPR32000			(32000)
#define	I810_SAMPR33075			(33075)
#define	I810_SAMPR37800			(37800)
#define	I810_SAMPR44100			(44100)
#define	I810_SAMPR48000			(48000)

#define	I810_DEFAULT_SR			I810_SAMPR8000
#define	I810_DEFAULT_CH			AUDIO_CHANNELS_MONO
#define	I810_DEFAULT_PREC		AUDIO_PRECISION_8
#define	I810_DEFAULT_ENC		AUDIO_ENCODING_ULAW
#define	I810_DEFAULT_PGAIN		(AUDIO_MAX_GAIN * 3 / 4)
#define	I810_DEFAULT_RGAIN		(127)
#define	I810_DEFAULT_MONITOR_GAIN	(0)
#define	I810_DEFAULT_BAL		AUDIO_MID_BALANCE
#define	I810_INTS			(175)	/* default interrupt rate */
#define	I810_MIN_INTS			(24)	/* minimum interrupt rate */
#define	I810_MAX_INTS			(5000)	/* maximum interrupt rate */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_AUDIO810_H_ */
