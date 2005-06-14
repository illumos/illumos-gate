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
 * This header file defines the internal interfaces for the audio support
 * module. It is NOT to be distributed with Solaris.
 */

#ifndef	_SYS_AUDIO_SUPPORT_IMPL_H
#define	_SYS_AUDIO_SUPPORT_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	AUDIO_MINOR_AUDIO		0	/* /dev/audio */
#define	AUDIO_MINOR_AUDIOCTL		1	/* /dev/audioctl */
#define	AUDIO_MINOR_WAVE_TABLE		2	/* reserved for future */
#define	AUDIO_MINOR_MIDI_PORT		3	/* reserved for future */
#define	AUDIO_MINOR_TIME		4	/* reserved for future */
#define	AUDIO_MINOR_USER1		7	/* reserved for future */
#define	AUDIO_MINOR_USER2		8	/* reserved for future */
#define	AUDIO_MINOR_USER3		9	/* reserved for future */

#define	AUDIO_MAX(a, b)			((a) > (b) ? (a) : (b))
#define	AUDIO_MAX4(w, x, y, z)		AUDIO_MAX(AUDIO_MAX(w, x), \
						AUDIO_MAX(y, z))

/* audio support ioctl/iocdata commands */
#define	AUDIO_COPY_OUT_CH_NUMBER	(AIOC|1)	/* AUDIO_GET_CH_NUM */
#define	AUDIO_COPY_OUT_CH_TYPE		(AIOC|2)	/* AUDIO_GET_CH_TYPE */
#define	AUDIO_COPY_OUT_NUM_CHS		(AIOC|3)	/* AUDIO_GET_NUM_CHS */
#define	AUDIO_COPY_OUT_AD_DEV		(AIOC|4)	/* AUDIO_GET_AD_DEV */
#define	AUDIO_COPY_OUT_APM_DEV		(AIOC|5)	/* AUDIO_GET_APM_DEV */
#define	AUDIO_COPY_OUT_AS_DEV		(AIOC|6)	/* AUDIO_GET_AS_DEV */

/*
 * Macros used to convert between the opaque audio taskq handles and the
 * true taskq handles. Also standard taskq defines.
 */
#define	AUDIO_AUDIOTQHDL2TQHDL(atqhdl)		((taskq_t *)(atqhdl))
#define	AUDIO_TQHDL2AUDIOTQHDL(tqhdl)		((audio_taskq_t)(tqhdl))

#define	AUDIO_SUP_TASKQ_NTHREADS		(1)
#define	AUDIO_SUP_TASKQ_MINALLOC		4	/* min taskq structs */
#define	AUDIO_SUP_TASKQ_MAXALLOC		100	/* max taskq structs */

/*
 * audio_inst_list_t	- structure that describes the audio device instance
 */
struct audio_inst_info {
	struct audio_inst_info  *ail_next;	/* linking in driver list */
	audio_state_t		ail_state;	/* state struct for this inst */
};
typedef struct audio_inst_info audio_inst_info_t;

/*
 * audio_qptr_t		- structure used to store private data in the STREAM
 */
struct audio_qptr {
	dev_t			aq_dev;		/* device name */
	void			*aq_data;	/* STREAM private data */
};
typedef struct audio_qptr audio_qptr_t;

/* audiosup module key for persistent memory, one per system */
#define	AUDIO_SUP_KEY			"AUDIO:audiosup master anchor key"

/* audiosup module instance key for persistent memory, one per dev instance */
#define	AUDIO_KEY_CLASS			"AUDIO:"

/*
 * audio_apm_persist_t	- structure for instance APM persistent memory storage
 */
struct audio_apm_persist {
	audio_device_type_e	ap_apm_type;	/* APM type, one per instance */
	void			*ap_data;	/* per APM data */
	size_t			ap_size;	/* size of the data */
	struct audio_apm_persist *ap_next;	/* next item */
};
typedef struct audio_apm_persist audio_apm_persist_t;

/*
 * audio_inst_persist_t	- instance persistent data
 */
struct audio_inst_persist {
	char			*amp_key;	/* persistent data key */
	major_t			amp_major;	/* device major number */
	int			amp_instance;	/* instance number */
	audio_apm_persist_t	*amp_apmp;	/* ptr to APM persistent data */
	struct audio_inst_persist *amp_next;	/* next structure */
};
typedef struct audio_inst_persist audio_inst_persist_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AUDIO_SUPPORT_IMPL_H */
