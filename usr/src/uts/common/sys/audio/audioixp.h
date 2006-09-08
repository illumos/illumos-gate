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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_AUDIOIXP_H_
#define	_SYS_AUDIOIXP_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Header file for the audioixp device driver
 */

/*
 * Values returned by the AUDIO_GETDEV ioctl()
 */
#define	IXP_DEV_NAME		"SUNW,audioixp"
#define	IXP_DEV_CONFIG		"onboard1"
#define	IXP_DEV_VERSION		"a"

/*
 * Driver supported configuration information
 */
#define	IXP_NAME		"audioixp"
#define	IXP_MOD_NAME		"mixer audio driver"

#define	IXP_SAMPR8000		(8000)
#define	IXP_SAMPR11025		(11025)
#define	IXP_SAMPR16000		(16000)
#define	IXP_SAMPR22050		(22050)
#define	IXP_SAMPR24000		(24000)
#define	IXP_SAMPR32000		(32000)
#define	IXP_SAMPR44100		(44100)
#define	IXP_SAMPR48000		(48000)

#define	IXP_DEFAULT_SR		IXP_SAMPR8000
#define	IXP_DEFAULT_CH		AUDIO_CHANNELS_MONO
#define	IXP_DEFAULT_PREC	AUDIO_PRECISION_8
#define	IXP_DEFAULT_ENC		AUDIO_ENCODING_ULAW
#define	IXP_DEFAULT_PGAIN	(AUDIO_MAX_GAIN * 3 / 4)
#define	IXP_DEFAULT_RGAIN		(127)
#define	IXP_DEFAULT_MONITOR_GAIN	(0)
#define	IXP_DEFAULT_BAL		AUDIO_MID_BALANCE
#define	IXP_INTS		(175)	/* default interrupt rate */
#define	IXP_MIN_INTS		(24)	/* minimum interrupt rate */
#define	IXP_MAX_INTS		(500)	/* maximum interrupt rate */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_AUDIOIXP_H_ */
