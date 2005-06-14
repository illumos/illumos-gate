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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * This header file defines the public interfaces for the audio mixer
 * sample rate conversion routines. Only the audio mixer and sample rate
 * conversion routines may include this header file.
 *
 * CAUTION: This header file has not gone through a formal review process.
 *	Thus its commitment level is very low and may change or be removed
 *	at any time.
 */

#ifndef	_SYS_AUDIO_SRC_H
#define	_SYS_AUDIO_SRC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#define	AM_SRC_VERSION		AM_SRC_VERSION2
#define	AM_SRC_VERSION2		2

/*
 * The handle used by the mixer and the sample rate conversion routine.
 */
typedef struct src_handle *srchdl_t;

/*
 * am_ad_src_entry_t	- Audio Driver sample rate conversion routines
 */
struct am_ad_src_entry {
	int		ad_version;
	size_t		(*ad_src_init)(srchdl_t handle, int dir);
	void		(*ad_src_exit)(srchdl_t handle, int dir);
	int		(*ad_src_update)(srchdl_t handle,
			    audio_prinfo_t *ch_prinfo,
			    audio_prinfo_t *hw_prinfo,
			    void *src_info, int dir);
	int		(*ad_src_adjust)(srchdl_t handle, int dir,
			    int samples);
	int		*(*ad_src_convert)(srchdl_t handle, int channels,
			    int dir, int *src, int *ptr1, int *ptr2,
			    int *samples);
	size_t		(*ad_src_size)(srchdl_t handle, audio_prinfo_t *prinfo,
			    int dir, int samples, int hw_channels);
};
typedef struct am_ad_src_entry am_ad_src_entry_t;

/*
 * am_ad_sample_rates_t		- supported sample rates
 */
struct am_ad_sample_rates {
	int		ad_limits;	/* 0 if sample rates not limits */
	uint_t		*ad_srs;	/* NULL term. list of sample rates */
};
typedef struct am_ad_sample_rates am_ad_sample_rates_t;

/* am_ad_ample_rates.ad_limits */
#define	MIXER_SRS_FLAG_SR_NOT_LIMITS	0x00000000u
						/* samp rates not limits */
#define	MIXER_SRS_FLAG_SR_LIMITS	MIXER_SR_LIMITS
						/* samp rates set limits */

/*
 * Audio Mixer Audio Driver Miscellaneous Routines
 */
void *am_get_src_data(srchdl_t handle, int dir);
void am_set_src_data(srchdl_t handle, int dir, void *data);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AUDIO_SRC_H */
