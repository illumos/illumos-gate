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

#ifndef _SYS_AUDIO_4231_H
#define	_SYS_AUDIO_4231_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Header file for the audiocs device driver.
 */

/*
 * Values returned by the AUDIO_GETDEV ioctl()
 */
#define	CS_DEV_NAME		"SUNW,CS4231"
#define	CS_DEV_CONFIG_ONBRD1	"onboard1"
#define	CS_DEV_VERSION		"a"	/* SS5 				*/
#define	CS_DEV_VERSION_A	CS_DEV_VERSION
#define	CS_DEV_VERSION_B	"b"	/* Electron - internal loopback	*/
#define	CS_DEV_VERSION_C	"c"	/* Positron			*/
#define	CS_DEV_VERSION_D	"d"	/* PowerPC - Retired		*/
#define	CS_DEV_VERSION_E	"e"	/* x86 - Retired		*/
#define	CS_DEV_VERSION_F	"f"	/* Tazmo			*/
#define	CS_DEV_VERSION_G	"g"	/* Quark Audio Module		*/
#define	CS_DEV_VERSION_H	"h"	/* Darwin			*/

/*
 * Driver supported configuration information
 */
#define	CS4231_NAME		"audiocs"
#define	CS4231_MOD_NAME		"CS4231 mixer audio driver"

#define	CS4231_SAMPR5510	(5510)
#define	CS4231_SAMPR6620	(6620)
#define	CS4231_SAMPR8000	(8000)
#define	CS4231_SAMPR9600	(9600)
#define	CS4231_SAMPR11025	(11025)
#define	CS4231_SAMPR16000	(16000)
#define	CS4231_SAMPR18900	(18900)
#define	CS4231_SAMPR22050	(22050)
#define	CS4231_SAMPR27420	(27420)
#define	CS4231_SAMPR32000	(32000)
#define	CS4231_SAMPR33075	(33075)
#define	CS4231_SAMPR37800	(37800)
#define	CS4231_SAMPR44100	(44100)
#define	CS4231_SAMPR48000	(48000)

#define	CS4231_DEFAULT_SR	CS4231_SAMPR8000
#define	CS4231_DEFAULT_CH	AUDIO_CHANNELS_MONO
#define	CS4231_DEFAULT_PREC	AUDIO_PRECISION_8
#define	CS4231_DEFAULT_ENC	AUDIO_ENCODING_ULAW
#define	CS4231_DEFAULT_PGAIN	AUDIO_MID_GAIN
#define	CS4231_DEFAULT_RGAIN	AUDIO_MID_GAIN
#define	CS4231_DEFAULT_MONITOR_GAIN	(0)
#define	CS4231_DEFAULT_BAL	AUDIO_MID_BALANCE	/* MUST be mid */
#define	CS4231_INTS		(175)		/* default interrupt rate */
#define	CS4231_MIN_INTS		(10)		/* minimum interrupt rate */
#define	CS4231_MAX_INTS		(2000)		/* maximum interrupt rate */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_AUDIO_4231_H */
