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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/*
 * Miscellaneous defines
 */
#define	AM_MAX_QUEUED_MSGS_SIZE		(49000*2*4)	/* ~1 secs of audio */
#define	AM_MIN_QUEUED_MSGS_SIZE		(24500*2*4)	/* ~0.5 secs of audio */

/*
 * am_ad_ch_cap_t	- Audio Driver play/record capabilities
 */
struct am_ad_ch_cap {
	am_ad_sample_rates_t	ad_mixer_srs;	/* mixer mode sample rates */
	am_ad_sample_rates_t	ad_compat_srs;	/* compat mode sample rates */
	am_ad_src_entry_t	*ad_conv;	/* sample rate conv. routines */
	void			*ad_sr_info;	/* sample rate conv. info */
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
	int		(*ad_setup)(audiohdl_t handle, int stream, int flags);
	void		(*ad_teardown)(audiohdl_t handle, int stream, int dir);
	int		(*ad_set_config)(audiohdl_t handle, int stream,
				int command, int dir, int arg1, int arg2);
	int		(*ad_set_format)(audiohdl_t handle, int stream,
				int dir, int sample_rate, int channels,
				int precision, int encoding);
	int		(*ad_start_play)(audiohdl_t handle, int stream);
	void		(*ad_pause_play)(audiohdl_t handle, int stream);
	void		(*ad_stop_play)(audiohdl_t handle, int stream);
	int		(*ad_start_record)(audiohdl_t handle, int stream);
	void		(*ad_stop_record)(audiohdl_t handle, int stream);
	int		(*ad_ioctl)(audiohdl_t handle, int channel,
				queue_t *q, mblk_t *mp, int *error);
	int		(*ad_iocdata)(audiohdl_t handle, int channel,
				queue_t *q, mblk_t *mp, int *error);
};
typedef struct am_ad_entry am_ad_entry_t;

/* ad_set_config() and ad_set_format() stream # */
#define	AM_SET_CONFIG_BOARD	(-1)	/* for the whole board */

/* ad_set_config() commands */
#define	AM_SET_GAIN		0x01	/* set input/ouput channel gain */
#define	AM_SET_GAIN_BAL		0x02	/* set input/ouput channel gain */
#define	AM_SET_PORT		0x03	/* set input/output port */
#define	AM_SET_MONITOR_GAIN	0x04	/* set monitor gain */
#define	AM_OUTPUT_MUTE		0x05	/* mute output */
#define	AM_MONO_MIC		0x06	/* set which mono microphone */
#define	AM_MIC_BOOST		0x07	/* enable/disable mic preamp */
#define	AM_BASS_BOOST		0x08	/* boost output bass */
#define	AM_MID_BOOST		0x09	/* boost output mid range */
#define	AM_TREBLE_BOOST		0x0a	/* boost output treble */
#define	AM_LOUDNESS		0x0b	/* enable/disable output loudness */
#define	AM_SET_DIAG_MODE	0x0c	/* set diagnostics mode */

/*
 * am_ad_info_t	- Audio Driver configuration information structure
 */
struct am_ad_info {
	int		ad_int_vers;	/* Audio Driver interface version */
	int		ad_mode;	/* MIXER or COMPAT mode */
	uint_t		ad_add_mode;	/* additional mode information */
	int		ad_codec_type;	/* Codec type */
	audio_info_t	*ad_defaults;	/* Audio Driver audio_info_t struct */
	am_ad_ch_cap_t	ad_play;	/* play capabilities */
	am_ad_ch_cap_t	ad_record;	/* record capabilities */
	am_ad_cap_comb_t *ad_play_comb;	/* list of play cap. combinations */
	am_ad_cap_comb_t *ad_rec_comb;	/* list of rec cap. combinations */
	am_ad_entry_t	*ad_entry;	/* Audio Driver entry points */
	audio_device_t	*ad_dev_info;	/* device information */
	uint_t		ad_diag_flags;	/* flags that specify diagnostics sup */
	uint_t		ad_diff_flags;	/* format difference flags */
	uint_t		ad_assist_flags; /* audio stream assist flags */
	uint_t		ad_misc_flags;	/* misc. flags */
	uint_t		ad_translate_flags; /* translate flags */
	int		ad_num_mics;	/* # of mic inputs */
	uint_t		_xxx[4];	/* reserved for future use */
};
typedef struct am_ad_info am_ad_info_t;

/* the taskq lock must be held in order for ad_mode to be valid */
_NOTE(SCHEME_PROTECTS_DATA("method", am_ad_info::ad_mode))

/* am_ad_info.ad_int_vers defines */
#define	AM_VERSION	AM_VERS2
#define	AM_VERS2	2		/* Supported interface version */

/* am_ad_info.ad_add_mode defines */
#define	AM_ADD_MODE_DIAG_MODE	0x00000001u	/* dev supports diagnostics */
#define	AM_ADD_MODE_MIC_BOOST	0x00000002u	/* mic boost enabled */

/* am_ad_info.ad_codec_type defines */
#define	AM_TRAD_CODEC		0x00000001u	/* traditional Codec */
#define	AM_MS_CODEC		0x00000002u	/* multi-stream Codec */

/* am_ad_info.ad_diag_flags defines */
#define	AM_DIAG_INTERNAL_LOOP	0x00000001u	/* dev has internal loopbacks */

/* am_ad_info.ad_diff_flags defines */
#define	AM_DIFF_SR		0x00000001u	/* p/r sample rate may differ */
#define	AM_DIFF_CH		0x00000002u	/* p/r channels may differ */
#define	AM_DIFF_PREC		0x00000004u	/* p/r precision may differ */
#define	AM_DIFF_ENC		0x00000008u	/* p/r encoding may differ */

/* am_ad_info.ad_assist_flags defines */
#define	AM_ASSIST_BASE		0x00000001u	/* device has base boost */
#define	AM_ASSIST_MID		0x00000002u	/* device has mid range boost */
#define	AM_ASSIST_TREBLE	0x00000004u	/* device has treble boost */
#define	AM_ASSIST_LOUDNESS	0x00000008u	/* device has loudness boost */
#define	AM_ASSIST_MIC		0x00000010u	/* mic has preamp boost */

/* am_ad_info.ad_misc_flags defines */
#define	AM_MISC_PP_EXCL		0x00000001u	/* play ports are exclusive */
#define	AM_MISC_RP_EXCL		0x00000002u	/* record ports are exclusive */
#define	AM_MISC_MONO_MIC	0x00000004u	/* mono mic */
#define	AM_MISC_MONO_DUP	0x00000008u	/* mono is duped to all chs */

/* am_ad_info.ad_translate_flags */
#define	AM_MISC_8_P_TRANSLATE	0x00000001u	/* trans. signed to unsigned */
#define	AM_MISC_16_P_TRANSLATE	0x00000002u	/* trans. signed to unsigned */
#define	AM_MISC_8_R_TRANSLATE	0x00010000u	/* trans. unsigned to signed */
#define	AM_MISC_16_R_TRANSLATE	0x00020000u	/* trans. unsigned to signed */

/*
 * Support for custom audio driver ioctl()s.
 */
#define	AM_WIOCDATA			0	/* returned by Audio Driver */
#define	AM_ACK				1	/* with private ioctl() & */
#define	AM_NACK				2	/* iocdata() routines */

/*
 * Audio Mixer Driver Entry Point Routines
 */
int am_attach(audiohdl_t handle, ddi_attach_cmd_t cmd, am_ad_info_t *ad_infop);
int am_detach(audiohdl_t handle, ddi_detach_cmd_t cmd);

/*
 * Audio Mixer Driver Device Dependent Driver Play Routines
 */
int am_get_audio(audiohdl_t handle, void *buf, int channel, int samples);
void am_play_shutdown(audiohdl_t handle, int channel);

/*
 * Audio Mixer Driver Device Dependent Driver Record Routines
 */
void am_send_audio(audiohdl_t handle, void *buf, int channel, int samples);

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
