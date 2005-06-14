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
 * Copyright 1999-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * This header file defines the audio support module's public interfaces
 * that may be used by audio personality modules. Audio drivers must NOT
 * include this header file.
 *
 * CAUTION: This header file has not gone through a formal review process.
 *	Thus its commitment level is very low and may change or be removed
 *	at any time.
 */

#ifndef	_SYS_AUDIO_APM_H
#define	_SYS_AUDIO_APM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/*
 * Miscellaneous defines.
 */
#define	AUDIO_NUM_DEVS		10	/* /dev/audio, /dev/audioctl, etc. */
#define	AUDIO_MINOR_PER_INST	128	/* max # of channels to each instance */
#define	AUDIO_MIN_CLONE_CHS	1	/* minimum number of clone channels */
#define	AUDIO_CLONE_CHANLIM	(AUDIO_MINOR_PER_INST - AUDIO_NUM_DEVS)
					/* max # of clones to each instance */

#define	AUDIO_MINOR_TO_INST(d)	(getminor(d) >> 7)

#define	AUDIO_TASKQ_SUSPENDED	0
#define	AUDIO_TASKQ_RUNNING	(~AUDIO_TASKQ_SUSPENDED)

/*
 * audio_data_t		- struct used to store original and processed audio data
 */
struct audio_data {
	void			*adata_orig;	/* the original data */
	void			*adata_optr;	/* marker into the orig. data */
	void			*adata_oeptr;	/* end of the original data */
	size_t			adata_osize;	/* size of the original data */
	void			*adata_proc;	/* the processed data */
	void			*adata_pptr;	/* marker into the proc. data */
	void			*adata_peptr;	/* ptr to end of proc. data */
	size_t			adata_psize;	/* size of the processed data */
	struct audio_data	*adata_next;	/* pointer to the next struct */
};
typedef struct audio_data audio_data_t;

/*
 * The members of the audio_data structure, except adata_next, are protected
 * by scheme because audio_sup_get_audio_data() removes one of these structures
 * from the list and only that thread has access to the data structure.
 */
_NOTE(SCHEME_PROTECTS_DATA("private data", audio_data::adata_orig))
_NOTE(SCHEME_PROTECTS_DATA("private data", audio_data::adata_optr))
_NOTE(SCHEME_PROTECTS_DATA("private data", audio_data::adata_oeptr))
_NOTE(SCHEME_PROTECTS_DATA("private data", audio_data::adata_osize))
_NOTE(SCHEME_PROTECTS_DATA("private data", audio_data::adata_proc))
_NOTE(SCHEME_PROTECTS_DATA("private data", audio_data::adata_pptr))
_NOTE(SCHEME_PROTECTS_DATA("private data", audio_data::adata_peptr))
_NOTE(SCHEME_PROTECTS_DATA("private data", audio_data::adata_psize))

/*
 * audio_ch_t		- per channel state and operation data
 */
struct audio_ch {
	queue_t			*ch_qptr;	/* channel queue pointer */
	struct audio_state	*ch_statep;	/* channel instance state ptr */
	kmutex_t		ch_lock;	/* channel lock */
	kcondvar_t		ch_cv;		/* available for use by ch */
	struct audio_apm_info	*ch_apm_infop;	/* pointer to ch APM info */
	int			(*ch_wput)(queue_t *, mblk_t *);
						/* APM's write put rtn */
	int			(*ch_wsvc)(queue_t *);
						/* APM's write svc rtn */
	int			(*ch_rput)(queue_t *, mblk_t *);
						/* APM's read put routine */
	int			(*ch_rsvc)(queue_t *);
						/* APM's read svc routine */
	int			ch_dir;		/* I/O direction */
	uint_t			ch_flags;	/* channel state flags */
	dev_t			ch_dev;		/* channel device number */
	void			*ch_private;	/* channel private data */
	audio_channel_t		ch_info;	/* channel state info */
	audio_device_t		*ch_dev_info;	/* Audio Driver device info */
	kmutex_t		ch_adata_lock;	/* audio data list lock */
	audio_data_t		*ch_adata;	/* audio data structure list */
	audio_data_t		*ch_adata_end;	/* end of audio data list */
	int			ch_adata_cnt;	/* # of queued data structs */
};
typedef struct audio_ch audio_ch_t;

_NOTE(MUTEX_PROTECTS_DATA(audio_ch::ch_lock, audio_ch))

_NOTE(MUTEX_PROTECTS_DATA(audio_ch::ch_adata_lock, audio_ch::ch_adata))
_NOTE(MUTEX_PROTECTS_DATA(audio_ch::ch_adata_lock, audio_ch::ch_adata_cnt))
_NOTE(MUTEX_PROTECTS_DATA(audio_ch::ch_adata_lock, audio_ch::ch_adata_end))
_NOTE(MUTEX_PROTECTS_DATA(audio_ch::ch_adata_lock, audio_data::adata_next))

/*
 * Further analysis is needed for these structure members. We are
 * deferring this analysis until later.
 */
_NOTE(DATA_READABLE_WITHOUT_LOCK(audio_ch::ch_qptr))
_NOTE(DATA_READABLE_WITHOUT_LOCK(audio_ch::ch_statep))
_NOTE(DATA_READABLE_WITHOUT_LOCK(audio_ch::ch_apm_infop))
_NOTE(DATA_READABLE_WITHOUT_LOCK(audio_ch::ch_wput))
_NOTE(DATA_READABLE_WITHOUT_LOCK(audio_ch::ch_wsvc))
_NOTE(DATA_READABLE_WITHOUT_LOCK(audio_ch::ch_rput))
_NOTE(DATA_READABLE_WITHOUT_LOCK(audio_ch::ch_rsvc))
_NOTE(DATA_READABLE_WITHOUT_LOCK(audio_ch::ch_dir))
_NOTE(DATA_READABLE_WITHOUT_LOCK(audio_ch::ch_private))
_NOTE(DATA_READABLE_WITHOUT_LOCK(audio_ch::ch_info))
_NOTE(DATA_READABLE_WITHOUT_LOCK(audio_ch::ch_dev_info))
_NOTE(DATA_READABLE_WITHOUT_LOCK(audio_ch::ch_dev))

/* audio_ch.ch_flags defines */
#define	AUDIO_CHNL_ALLOCATED	0x0001u		/* the channel is allocated */
#define	AUDIO_CHNL_ACTIVE	0x0002u		/* the channel is active */

/*
 * audio_state_t	- per instance state and operation data
 */
struct audio_state {
	kmutex_t		as_lock;	/* instance state lock */
	kcondvar_t		as_cv;		/* cv for blocked ch alloc */
	int			as_max_chs;	/* max # of open channels */
	int			as_minors_per_inst; /* #minors per instance */
	int			as_audio_reserved; /* #audio devices */
	dev_info_t		*as_dip;	/* known at attach time */
	int			as_dev_instance; /* Audio Driver dev inst. # */
	major_t			as_major;	/* Audio Driver major number */
	uint_t			as_ch_inuse;	/* # of channels in use */
	struct audio_apm_info	*as_apm_info_list;	/* APM info list */
	void			*as_private;	/* private audio driver data */
	void			*as_persistp;	/* persistent data */
	audio_ch_t		as_channels[AUDIO_CLONE_CHANLIM]; /* channels */
};
typedef struct audio_state audio_state_t;

_NOTE(MUTEX_PROTECTS_DATA(audio_state::as_lock, audio_state))

/* these audio_state structure members are read only once set */
_NOTE(DATA_READABLE_WITHOUT_LOCK(audio_state::as_max_chs))
_NOTE(DATA_READABLE_WITHOUT_LOCK(audio_state::as_dip))
_NOTE(DATA_READABLE_WITHOUT_LOCK(audio_state::as_dev_instance))
_NOTE(DATA_READABLE_WITHOUT_LOCK(audio_state::as_max_chs))
_NOTE(DATA_READABLE_WITHOUT_LOCK(audio_state::as_audio_reserved))
_NOTE(DATA_READABLE_WITHOUT_LOCK(audio_state::as_minors_per_inst))

/*
 * Further analysis is needed for this structure member. We are
 * deferring this analysis until later.
 */
_NOTE(SCHEME_PROTECTS_DATA("private data", audio_state::as_private))

/*
 * audio_apm_info_t	- audio personality module state information
 */
struct audio_apm_info {
	kmutex_t		apm_lock;	/* APM structure state lock */
	int			(*apm_open)(queue_t *, dev_t *,
						int, int, cred_t *);
						/* APM open() routine */
	int			(*apm_close)(queue_t *, int, cred_t *);
						/* APM close() routine */
	int			(*apm_restore_state)(audio_state_t *,
				    struct audio_apm_info *, int);
						/* APM state retsore routine */
	int			(*apm_save_state)(audio_state_t *,
				    struct audio_apm_info *, int);
						/* APM state save routine */
	audio_device_t		*apm_info;	/* audio_device_t structure */
	audio_device_type_e	apm_type;	/* the device type */
	void			*apm_private;	/* private APM data */
	void			*apm_ad_infop;	/* device capabilities */
	void			*apm_ad_state;	/* state of the device */
	struct audio_apm_info	*apm_next;	/* pointer to the next struct */
};
typedef struct audio_apm_info audio_apm_info_t;

_NOTE(MUTEX_PROTECTS_DATA(audio_apm_info::apm_lock, audio_apm_info))
/* these audio_apm_info structure members are read only once set */
_NOTE(DATA_READABLE_WITHOUT_LOCK(
    audio_apm_info::apm_private		audio_apm_info::apm_type
    audio_apm_info::apm_close		audio_apm_info::apm_open
    audio_apm_info::apm_restore_state	audio_apm_info::apm_save_state
    audio_apm_info::apm_info		audio_apm_info::apm_ad_infop
    audio_apm_info::apm_ad_state))
_NOTE(DATA_READABLE_WITHOUT_LOCK(audio_apm_info::apm_next))
_NOTE(MUTEX_PROTECTS_DATA(audio_state::as_lock, audio_apm_info::apm_next))

/*
 * audio_apm_reg	- This structure holds all of the data needed to
 *			  register an Audio Personality Module for use.
 */
struct audio_apm_reg {
	int		aar_version;		/* structure version */
	int		(*aar_apm_open)
			    (queue_t *q, dev_t *devp, int flag, int sflags,
			    cred_t *credp);
						/* APM open() routine */
	int		(*aar_apm_close)(queue_t *q, int flag, cred_t *credp);
						/* APM close() routine */
	int		(*aar_apm_save_state)(audio_state_t *statep,
			    audio_apm_info_t *, int);
						/* APM save routine */
	int		(*aar_apm_restore_state)(audio_state_t *statep,
			    audio_apm_info_t *, int dir);
						/* APM restore routine */
	void		*aar_private;		/* APM private data */
	void		*aar_info;		/* APM info structure */
	void		*aar_state;		/* APM state structure */
	audio_device_t	*aar_dev_info;		/* APM device info pointer */
};
typedef struct audio_apm_reg audio_apm_reg_t;
#define	AM_AAR_VERSION		AM_AAR_VERS1
#define	AM_AAR_VERS1		1		/* supported register version */

/*
 * Macros used to convert between audio handles and the state structure.
 */
#define	AUDIO_HDL2STATE(hdl)		((audio_state_t *)(hdl))
#define	AUDIO_STATE2HDL(statep)		((audiohdl_t)(statep))

/*
 * Audio Support Module Channel Routines
 */
audio_ch_t *audio_sup_alloc_ch(audio_state_t *statep, int *error,
    audio_device_type_e type, int oflag);
int audio_sup_free_ch(audio_ch_t *chptr);

/*
 * Audio Support Module State Routines
 */
audio_state_t *audio_sup_devt_to_state(dev_t dev);
audio_state_t *audio_sup_devinfo_to_state(dev_info_t *dip);

/*
 * Audio Support Module Persistent Memory Routines
 */
void *audio_sup_get_persist_state(audio_state_t *state,
    audio_device_type_e dev_type);
int audio_sup_free_persist_state(audio_state_t *state,
    audio_device_type_e dev_type);
int audio_sup_set_persist_state(audio_state_t *state,
    audio_device_type_e dev_type, void *state_data, size_t state_size);

/*
 * Audio Support Module Minor Routines
 */
int audio_sup_ch_to_minor(audio_state_t *statep, int channel);
int audio_sup_minor_to_ch(audio_state_t *statep, minor_t minor);
int audio_sup_type_to_minor(audio_device_type_e type);

/*
 * Audio Support Module Audio Data Routines
 */
void audio_sup_flush_audio_data(audio_ch_t *chptr);
void audio_sup_free_audio_data(audio_data_t *adata);
audio_data_t *audio_sup_get_audio_data(audio_ch_t *chptr);
int audio_sup_get_audio_data_cnt(audio_ch_t *chptr);
int audio_sup_get_audio_data_size(audio_ch_t *chptr);
void audio_sup_putback_audio_data(audio_ch_t *chptr, audio_data_t *adata);
int audio_sup_save_audio_data(audio_ch_t *chptr, void *adata_orig,
    size_t adata_osize, void *adata_proc, size_t adata_psize);

/*
 * Audio Support Module Registration Routines
 */
audio_apm_info_t *audio_sup_register_apm(audio_state_t *statep,
    audio_device_type_e type, audio_apm_reg_t *reg_info);
int audio_sup_unregister_apm(audio_state_t *statep, audio_device_type_e type);

/*
 * Audio Support Module Task Queue Routines
 */
audio_taskq_t audio_sup_taskq_create(const char *q_name);
void audio_sup_taskq_destroy(audio_taskq_t tq_handle);
int audio_sup_taskq_dispatch(audio_taskq_t tq_handle,
    void (*task_function)(void *arg), void *arg, int sleep);
void audio_sup_taskq_resume(audio_taskq_t tq_handle);
void audio_sup_taskq_suspend(audio_taskq_t tq_handle);
int audio_sup_taskq_suspended(audio_taskq_t tq_handle);
void audio_sup_taskq_wait(audio_taskq_t tq_handle);

/*
 * Audio Support Module Miscellaneous Routines
 */
audio_device_type_e audio_sup_devt_to_ch_type(audio_state_t *statep,
    dev_t dev);
int audio_sup_get_channel_number(queue_t *q);
audio_apm_info_t *audio_sup_get_apm_info(audio_state_t *statep,
    audio_device_type_e);
void *audio_sup_get_info(queue_t *q);
int audio_sup_mblk_alloc(mblk_t *mp, size_t size);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AUDIO_APM_H */
