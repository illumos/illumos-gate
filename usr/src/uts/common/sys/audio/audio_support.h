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
 *
 * This header file defines a legacy interface for audio drivers.
 * It should not be used in any code.
 *
 * CAUTION: This header file has not gone through a formal review process.
 *	Thus its commitment level is very low and may change or be removed
 *	at any time.
 */

#ifndef	_SYS_AUDIO_SUPPORT_H
#define	_SYS_AUDIO_SUPPORT_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/*
 * Internal audio interface return codes.
 */
#define	AUDIO_SUCCESS			(0)
#define	AUDIO_FAILURE			(-1)

/*
 * Opaque handle used by all audio drivers to reference the audio
 * support module and all audio personality modules.
 */
typedef struct audio_handle *audiohdl_t;

/*
 * Audio Support Module Entry Point Routines
 */
audiohdl_t audio_sup_register(dev_info_t *dip);
int audio_sup_unregister(audiohdl_t handle);
void audio_sup_restore_state(audiohdl_t handle);

/*
 * Audio Support Module Miscellaneous Routines
 */
void *audio_sup_get_private(audiohdl_t handle);
void audio_sup_set_private(audiohdl_t handle, void *private);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AUDIO_SUPPORT_H */
