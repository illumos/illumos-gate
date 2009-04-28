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
 * This header file defines the public interfaces for the audio mixer
 * audio personality module.
 *
 * CAUTION: This header file has not gone through a formal review process.
 *	Thus its commitment level is very low and may change or be removed
 *	at any time.
 */

#ifndef	_SYS_AUDIO_MIXER_H
#define	_SYS_AUDIO_MIXER_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/*
 * Miscellaneous defines
 */
struct am_ad_sample_rates {
	uint_t		*ad_srs;	/* NULL term. list of sample rates */
};
typedef struct am_ad_sample_rates am_ad_sample_rates_t;

/*
 * am_ad_ch_cap_t	- Audio Driver play/record capabilities
 */
struct am_ad_ch_cap {
	am_ad_sample_rates_t	ad_mixer_srs;	/* mixer mode sample rates */
	uint_t			*ad_chs;	/* list of channel types */
	int			ad_int_rate;	/* interrupt rate */
	int			ad_max_chs;	/* max channels */
	size_t			ad_bsize;	/* buffer size */
};
typedef struct am_ad_ch_cap am_ad_ch_cap_t;

/*
 * am_ad_cap_comb_t	- Audio Driver play/record capability combinations
 */
struct am_ad_cap_comb {
	int		ad_prec;	/* the data precision */
	int		ad_enc;		/* the data encoding method */
};
typedef struct am_ad_cap_comb am_ad_cap_comb_t;

/*
 * am_ad_entry_t	- Audio Driver ops vector definition
 */
struct am_ad_entry {
	int		(*ad_setup)(audiohdl_t handle, int flags);
	void		(*ad_teardown)(audiohdl_t handle, int dir);
	int		(*ad_set_config)(audiohdl_t handle,
				int command, int dir, int arg1, int arg2);
	int		(*ad_set_format)(audiohdl_t handle,
				int dir, int sample_rate, int channels,
				int precision, int encoding);
	int		(*ad_start_play)(audiohdl_t handle);
	void		(*ad_stop_play)(audiohdl_t handle);
	int		(*ad_start_record)(audiohdl_t handle);
	void		(*ad_stop_record)(audiohdl_t handle);
};
typedef struct am_ad_entry am_ad_entry_t;

/* ad_set_config() commands */
#define	AM_SET_GAIN		0x01	/* set input/ouput channel gain */
#define	AM_SET_PORT		0x03	/* set input/output port */
#define	AM_SET_MONITOR_GAIN	0x04	/* set monitor gain */
#define	AM_OUTPUT_MUTE		0x05	/* mute output */
#define	AM_MIC_BOOST		0x07	/* enable/disable mic preamp */

/*
 * am_ad_info_t	- Audio Driver configuration information structure
 */
struct am_ad_info {
	audio_info_t	*ad_defaults;	/* Audio Driver audio_info_t struct */
	am_ad_ch_cap_t	ad_play;	/* play capabilities */
	am_ad_ch_cap_t	ad_record;	/* record capabilities */
	am_ad_cap_comb_t *ad_play_comb;	/* list of play cap. combinations */
	am_ad_cap_comb_t *ad_rec_comb;	/* list of rec cap. combinations */
	am_ad_entry_t	*ad_entry;	/* Audio Driver entry points */
	audio_device_t	*ad_dev_info;	/* device information */
	int		ad_num_mics;	/* # of mic inputs */
};
typedef struct am_ad_info am_ad_info_t;

/* the taskq lock must be held in order for ad_mode to be valid */
_NOTE(SCHEME_PROTECTS_DATA("method", am_ad_info::ad_mode))

/*
 * Audio Mixer Driver Entry Point Routines
 */
int am_attach(audiohdl_t handle, ddi_attach_cmd_t cmd, am_ad_info_t *ad_infop);
int am_detach(audiohdl_t handle, ddi_detach_cmd_t cmd);

/*
 * Audio Mixer Driver Device Dependent Driver Play Routines
 */
int am_get_audio(audiohdl_t handle, void *buf, int samples);
void am_play_shutdown(audiohdl_t handle);

/*
 * Audio Mixer Driver Device Dependent Driver Record Routines
 */
void am_send_audio(audiohdl_t handle, void *buf, int samples);

/*
 * Audio Mixer Driver Device Dependent Driver Miscellaneous Routines
 */
int am_hw_state_change(audiohdl_t handle, int cmd, int dir, int value,
    int sleep);

/* am_hw_state_change() commands */
#define	AM_HWSC_SET_GAIN_DELTA	0x01
#define	AM_HWSC_SET_BAL_DELTA	0x02
#define	AM_HWSC_MUTE_TOGGLE	0x03
#define	AM_HWSC_ONLINE		0x04
#define	AM_HWSC_OFFLINE		0x05
#define	AM_HWSC_SET_GAIN_ABS	0x06
#define	AM_HWSC_SET_BAL_ABS	0x07

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AUDIO_MIXER_H */
