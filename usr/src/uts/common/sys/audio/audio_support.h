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
 *
 * This header file defines the public interfaces for the audio support
 * module. These definitions are available for use by all audio modules
 * and drivers.
 *
 * CAUTION: This header file has not gone through a formal review process.
 *	Thus its commitment level is very low and may change or be removed
 *	at any time.
 */

#ifndef	_SYS_AUDIO_SUPPORT_H
#define	_SYS_AUDIO_SUPPORT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
 * Miscellaneous defines.
 */
#define	AUDIO_PRECISION_SHIFT		3
#define	AUDIO_NO_CHANNEL		(-1)
#define	AUDIO_TOGGLE(X)			(X) ^= 1

/*
 * Opaque handle used by all audio drivers to reference the audio
 * support module and all audio personality modules.
 */
typedef struct audio_handle *audiohdl_t;

/*
 * Opaque handle used by all audio personality modules to reference the
 * audio task queue.
 */
typedef struct audio_taskq *audio_taskq_t;

/*
 * audio_i_state	- This structure is used to hold state information
 *			  between M_IOCTL and M_IOCDATA messages from the
 *			  STREAMS head.
 */
struct audio_i_state {
	long	ais_command;	/* the M_IOCDATA command to execute next */
	caddr_t	ais_address;	/* address to M_COPYOUT/M_COPYIN data from/to */
	caddr_t	ais_address2;	/* address to M_COPYOUT/M_COPYIN data from/to */
};
typedef struct audio_i_state audio_i_state_t;

/*
 * audio_sup_reg_data	- This structure is used to provide registration
 *			  data from the audio driver to the audiosup module.
 */
struct audio_sup_reg_data {
	int		asrd_version;	/* version of this data structure */
	char		*asrd_key;	/* unique string used to ID drvr inst */
};
typedef struct audio_sup_reg_data audio_sup_reg_data_t;

_NOTE(SCHEME_PROTECTS_DATA("private data", audio_sup_reg_data::asrd_key))

#define	AUDIOSUP_VERSION	AUDIOSUP_VERSION1
#define	AUDIOSUP_VERSION1	1

/*
 * Audio Support Module Entry Point Routines
 */
audiohdl_t audio_sup_register(dev_info_t *dip, audio_sup_reg_data_t *data);
int audio_sup_unregister(audiohdl_t handle);
int audio_sup_open(queue_t *q, dev_t *devp, int flag, int sflags,
    cred_t *credp);
int audio_sup_close(queue_t *q, int flag, cred_t *credp);
int audio_sup_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd,
    void *arg, void **result);
int audio_sup_restore_state(audiohdl_t handle, audio_device_type_e device,
    int dir);
int audio_sup_save_state(audiohdl_t handle, audio_device_type_e device,
    int dir);

#define	AUDIO_ALL_DEVICES	UNDEFINED

int audio_sup_rput(queue_t *q, mblk_t *mp);
int audio_sup_rsvc(queue_t *q);
int audio_sup_wput(queue_t *q, mblk_t *mp);
int audio_sup_wsvc(queue_t *q);

/*
 * Audio Support Module Entry Point Routines
 *	CAUTION: These routines will be removed from the next
 *		release of Solaris. Migrate to audio_sup_register()
 *		and audio_sup_unregister().
 */
audiohdl_t audio_sup_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
int audio_sup_detach(audiohdl_t handle, ddi_detach_cmd_t cmd);

/*
 * Audio Support Module STREAMS Private Data Routines
 */
void audio_sup_set_qptr(queue_t *q, dev_t dev, void *data);
void audio_sup_free_qptr(queue_t *q);
dev_t audio_sup_get_qptr_dev(queue_t *q);
void *audio_sup_get_qptr_data(queue_t *q);
int audio_sup_get_qptr_instance(queue_t *q);

/*
 * Audio Support Module Minor Routines
 */
int audio_sup_get_max_chs(audiohdl_t handle);
int audio_sup_get_minors_per_inst(audiohdl_t handle);
int audio_sup_construct_minor(audiohdl_t handle, audio_device_type_e type);
int audio_sup_devt_to_instance(dev_t devt);

/*
 * Audio Support Module Miscellaneous Routines
 */
dev_info_t *audio_sup_get_dip(audiohdl_t handle);
void *audio_sup_get_private(audiohdl_t handle);
void audio_sup_set_private(audiohdl_t handle, void *private);
/*PRINTFLIKE3*/
extern void audio_sup_log(audiohdl_t handle, uint_t level, char *fmt, ...)
    __KPRINTFLIKE(3);
int audio_sup_update_persist_key(dev_info_t *dip, char *new_key, int sleep);


#ifdef _SYSCALL32
/* ILP32 view of the audio_channel structure */
struct audio_channel32 {
	pid32_t			pid;		/* process ID */
	uint32_t		ch_number;	/* channel number */
	int32_t			dev_type;	/* device type */
	size32_t		info_size;	/* size of info structure */
	caddr32_t		info;		/* pointer to info structure */
};
#endif

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AUDIO_SUPPORT_H */
