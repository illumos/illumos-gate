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

#ifndef	_LX_AUDIO_H
#define	_LX_AUDIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/zone.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * name for this driver
 */
#define	LX_AUDIO_DRV			"lx_audio"

/*
 * names for the minor nodes this driver exports
 */
#define	LXA_MINORNAME_DEVCTL		"lx_devctl"
#define	LXA_MINORNAME_DSP		"lx_dsp"
#define	LXA_MINORNAME_MIXER		"lx_mixer"

/*
 * minor numbers for the minor nodes this driver exporrts
 */
#define	LXA_MINORNUM_DEVCTL		0
#define	LXA_MINORNUM_DSP		1
#define	LXA_MINORNUM_MIXER		2
#define	LXA_MINORNUM_COUNT		3

/*
 * driver ioctls
 *
 * note that we're layering on top of solaris audio devices so we want
 * to make sure that our ioctls namespace doesn't conflict with theirs.
 * looking in sys/audioio.h and sys/mixer.h we see that they seem to
 * use an _IO key of 'A' and 'M', so we'll choose an _IO key of 'a.'
 */

/*
 * administrative ioctls.
 * these ioctls are only supported on the DEVCTL minor node
 */
#define	LXA_IOC_ZONE_REG		(_IOR('a', 0, lxa_zone_reg_t))
#define	LXA_IOC_ZONE_UNREG		(_IOR('a', 1, lxa_zone_reg_t))


/*
 * audio and mixer device ioctls
 * these ioctls are supported on DSP and MIXER minor nodes.
 */
#define	LXA_IOC_GETMINORNUM		(_IOR('a', 20, int))

/*
 * audio device ioctls.
 * these ioctls are supports on DSP minor nodes.
 */
#define	LXA_IOC_MMAP_OUTPUT		(_IOR('a', 41, int))
#define	LXA_IOC_MMAP_PTR		(_IOR('a', 42, int))
#define	LXA_IOC_GET_FRAG_INFO		(_IOR('a', 43, lxa_frag_info_t))
#define	LXA_IOC_SET_FRAG_INFO		(_IOR('a', 44, lxa_frag_info_t))

/*
 * mixer device ioctls.
 * these ioctls are supports on MIXER minor nodes.
 */
#define	LXA_IOC_MIXER_GET_VOL		(_IOR('a', 60, lxa_mixer_levels_t))
#define	LXA_IOC_MIXER_SET_VOL		(_IOR('a', 61, lxa_mixer_levels_t))
#define	LXA_IOC_MIXER_GET_MIC		(_IOR('a', 62, lxa_mixer_levels_t))
#define	LXA_IOC_MIXER_SET_MIC		(_IOR('a', 63, lxa_mixer_levels_t))
#define	LXA_IOC_MIXER_GET_PCM		(_IOR('a', 64, lxa_mixer_levels_t))
#define	LXA_IOC_MIXER_SET_PCM		(_IOR('a', 65, lxa_mixer_levels_t))

/* command structure for LXA_IOC_ZONE_REG */
#define	LXA_INTSTRLEN 32
typedef struct lxa_zone_reg {
	char	lxa_zr_zone_name[ZONENAME_MAX];
	char	lxa_zr_inputdev[LXA_INTSTRLEN];
	char	lxa_zr_outputdev[LXA_INTSTRLEN];
} lxa_zone_reg_t;

/* command structure for LXA_IOC_GET_FRAG_INFO and LXA_IOC_SET_FRAG_INFO */
typedef struct lxa_frag_info {
	int	lxa_fi_size;
	int	lxa_fi_cnt;
} lxa_frag_info_t;

/* command structure for LXA_IOC_MIXER_GET_* and LXA_IOC_MIXER_SET_* */
typedef struct lxa_mixer_levels {
	int	lxa_ml_gain;
	int	lxa_ml_balance;
} lxa_mixer_levels_t;

/* verify that a solaris mixer level structure has valid values */
#define	LXA_MIXER_LEVELS_OK(x) (((x)->lxa_ml_gain >= AUDIO_MIN_GAIN) && \
				((x)->lxa_ml_gain <= AUDIO_MAX_GAIN) && \
				((x)->lxa_ml_balance >= AUDIO_LEFT_BALANCE) && \
				((x)->lxa_ml_balance <= AUDIO_RIGHT_BALANCE))

#ifdef	__cplusplus
}
#endif

#endif	/* _LX_AUDIO_H */
