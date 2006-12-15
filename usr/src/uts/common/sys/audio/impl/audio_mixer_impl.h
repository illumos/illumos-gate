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
 *
 * This header file defines the internal interfaces for the audio mixer
 * audio personality module. It is NOT to be distributed with Solaris or
 * included in any audio drivers.
 */

#ifndef	_SYS_AUDIO_MIXER_IMPL_H
#define	_SYS_AUDIO_MIXER_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	AM_MAX_GAIN_SHIFT		8	/* 1 more then 255, but close */
#define	AM_BALANCE_SHIFT		5

#define	AM_MIN_CHS			1

/*
 * Flow control is used to keep too many buffers from being allocated.
 * However, sometimes we come across apps that have a problem with flow
 * control. Therefore we can comment out and turn off flow control temporarily
 * so we can debug the app and come up with a work around.
 */
#define	FLOW_CONTROL

/*
 * Miscellaneous defines
 */
#define	AM_INT16_SHIFT			1
#define	AM_INT32_SHIFT			2
#define	AM_256_SHIFT			8
#define	AM_8_SHIFT			3
#define	AM_HALF_ENERGY_SHIFT		1
#define	AM_TIMES_2_SHIFT		1
#define	AM_TIMES_4_SHIFT		2
#define	AM_TIMES_8_SHIFT		3
#define	AM_TIMES_16_SHIFT		4
#define	AM_TIMES_32_SHIFT		5

#define	AM_MIN_MIX_BUFSIZE		48000
#define	AM_DEFAULT_MIX_BUFSIZE		(AM_MIN_MIX_BUFSIZE * 4 * 2)
#define	AM_MAX_QUEUED_MSGS_CNT		500
#define	AM_MIN_QUEUED_MSGS_CNT		200

#define	AM_DEFAULT_MIXER_GAIN		(AUDIO_MAX_GAIN*3/4)

#define	AM_MAX_QUEUED_MSGS		4

#define	AM_MAX_SAMPLES			(1024*1024)

#define	AM_SINGLE_OPEN			0
#define	AM_MULTIPLE_OPEN		1

#define	AM_NOT_MUTED			0
#define	AM_MUTED			(~AM_NOT_MUTED)

#define	AM_NO_FORCE			0
#define	AM_FORCE			(~AM_NO_FORCE)

#define	AM_NO_SERIALIZE			0
#define	AM_SERIALIZE			(~AM_NO_SERIALIZE)

#define	AM_MISC_MASK			0x00000003
#define	AM_CHAR2INT_MASK		0x000000ff

#define	AM_NO_PID			0
#define	AM_SET_WAITING			1
#define	AM_CLEAR_WAITING		0
#define	AM_SET_RECORD			1
#define	AM_NOT_RECORD			0
#define	AM_SET_PLAY			1
#define	AM_NOT_PLAY			0

#define	AM_EXTRA_SAMPLES		16

/* Private mixer return codes */
#define	AM_CHNL_CLOSED		(-2)	/* Channel closed while processing */

/*
 * The sample rate conversion handle is implemented as the channel pointer.
 * But the sample rate converter doesn't have to know about this at all.
 */
#define	AM_SRC_CHPTR2HDL(chptr)		((srchdl_t)(chptr))
#define	AM_SRC_HDL2CHPTR(hdl)		((audio_ch_t *)(hdl))

/* audio mixer ioctl/iocdata commands */
#define	AM_COPY_OUT_AUDIOINFO	(MIOC|1)	/* AUDIO_GETINFO */
#define	AM_COPY_OUT_AUDIOINFO2	(MIOC|2)	/* AUDIO_SETINFO */
#define	AM_COPY_IN_AUDIOINFO	(MIOC|3)	/* AUDIO_SETINFO */
#define	AM_COPY_IN_DIAG_LOOPB	(MIOC|4)	/* AUDIO_DIAG_LOOPBACK */
#define	AM_COPY_OUT_GETDEV	(MIOC|5)	/* AUDIO_GETDEV */
#define	AM_COPY_OUT_SAMP_RATES	(MIOC|6)	/* AUDIO_MIXER_GET_SAMPLE... */
#define	AM_COPY_IN_SAMP_RATES	(MIOC|7)	/* AUDIO_MIXER_GET_SAMPLE... */
#define	AM_COPY_IN_SAMP_RATES2	(MIOC|8)	/* AUDIO_MIXER_GET_SAMPLE... */
#define	AM_COPY_OUT_MIXCTLINFO	(MIOC|9)	/* AUDIO_MIXERCTL_GETINFO */
#define	AM_COPY_IN_MIXCTLINFO	(MIOC|10)	/* AUDIO_MIXERCTL_SETINFO */
#define	AM_COPY_OUT_MIXCTL_CHINFO (MIOC|11)	/* AUDIO_MIXERCTL_GET_CHINFO */
#define	AM_COPY_OUT_MIXCTL_CHINFO2 (MIOC|12)	/* AUDIO_MIXERCTL_GET_CHINFO */
#define	AM_COPY_IN_MIXCTL_GET_CHINFO (MIOC|13)	/* AUDIO_MIXERCTL_SET_CHINFO */
#define	AM_COPY_OUT_MIXCTL_GET_CHINFO (MIOC|14)	/* AUDIO_MIXERCTL_GET_CHINFO */
#define	AM_COPY_OUT_MIXCTL_GET_CHINFO2 (MIOC|15) /* AUDIO_MIXERCTL_GET_CHINFO */
#define	AM_COPY_IN_MIXCTL_SET_CHINFO (MIOC|16)	/* AUDIO_MIXERCTL_SET_CHINFO */
#define	AM_COPY_IN_MIXCTL_SET_CHINFO2 (MIOC|17)	/* AUDIO_MIXERCTL_SET_CHINFO */
#define	AM_COPY_OUT_MIXCTL_MODE	(MIOC|18)	/* AUDIO_MIXERCTL_GET_MODE */
#define	AM_COPY_IN_MIXCTL_MODE	(MIOC|19)	/* AUDIO_MIXERCTL_SET_MODE */

/*
 * am_ch_private_t	- audio mixer channel private data
 */
struct am_ch_private {
	uint_t			acp_flags;	/* channel flags */
	boolean_t		acp_reading;	/* true for RD channel */
	boolean_t		acp_writing;	/* true for WR channel */
	int			acp_EOF[2];	/* # of EOF signals to send */
	int			acp_EOF_toggle;	/* toggle for EOF signals */
	int			acp_psamples_f;	/* sample frame count mp_orig */
	int			acp_psamples_c;	/* samples in buf to play */
	int			acp_psamples_p;	/* samples in played buf */
	int			acp_busy_cnt;	/* # of calls outstanding */
	mblk_t			*acp_drain_mp;	/* saved mblk_t for DRAIN */
	mblk_t			*acp_rec_mp;	/* record message block */
	int			acp_rec_remaining; /* # bytes left in mp buf */
	int			*acp_play_samp_buf; /* play sample buf space */
	size_t			acp_psb_size;	/* size of play_samp_buf */
	void			*acp_play_src_data; /* play src data */
	void			*acp_rec_src_data; /* rec. src data */
	void			*acp_ch_psrc1;	/* play src buffer #1 */
	void			*acp_ch_psrc2;	/* play src buffer #2 */
	void			*acp_ch_pconv1;	/* play conversion buffer #1 */
	void			*acp_ch_pconv2;	/* play conversion buffer #1 */
	size_t			acp_ch_psrc_siz; /* play src buffer size */
	size_t			acp_ch_pconv_siz; /* play converter buf. size */
	size_t			acp_ch_pbuf_size; /* play prebuffer size */
	void			*acp_ch_rsrc1;	/* record src buffer #1 */
	void			*acp_ch_rsrc2;	/* record src buffer #2 */
	void			*acp_ch_rconv1;	/* record conv. buffer #1 */
	void			*acp_ch_rconv2;	/* record conv. buffer #1 */
	size_t			acp_ch_rsrc_siz; /* record src buffer size */
	size_t			acp_ch_rconv_siz; /* record converter buf siz */
	size_t			acp_ch_rbuf_size; /* record prebuffer size */
};
typedef struct am_ch_private am_ch_private_t;

_NOTE(MUTEX_PROTECTS_DATA(audio_ch::ch_lock, am_ch_private))
_NOTE(SCHEME_PROTECTS_DATA("method", am_ch_private::acp_play_src_data))
_NOTE(SCHEME_PROTECTS_DATA("method", am_ch_private::acp_rec_src_data))

/* am_ch_private.acp_flags defines */
#define	AM_CHNL_OPEN		0x00001u /* channel open if set */
#define	AM_CHNL_MULTI_OPEN	0x00002u /* PID may open multiple streams */
#define	AM_CHNL_DRAIN		0x00004u /* want drain semantics if set */
#define	AM_CHNL_DRAIN_NEXT_INT	0x00008u /* signal drain on next intr, step 1 */
#define	AM_CHNL_CLOSING		0x00010u /* the channel is being closed */
#define	AM_CHNL_ALMOST_EMPTY1	0x00020u /* 0 data for ch but data in DMA buf */
#define	AM_CHNL_ALMOST_EMPTY2	0x00040u /* 0 data for ch but data in DMA buf */
#define	AM_CHNL_EMPTY		0x00080u /* the channel doesn't have any data */
#define	AM_CHNL_CONTROL		0x00100u /* AUDIOCTL in same proc as AUDIO */
#define	AM_CHNL_CLIMIT		0x00200u /* used 2 limit allocb() failed msgs */
#define	AM_CHNL_PFLOW		0x00400u /* play side has been flow cntrlled */
#define	AM_CHNL_RSTREAMS_SET	0x00800u /* rec side's STREAMS H2O marks set */
#define	AM_CHNL_MSG_ON_QUEUE	0x01000u /* data message on STREAMS Q */
#define	AM_CHNL_IOCTL_TASK	0x08000u /* ioctl() task scheduled */
#define	AM_CHNL_QPROCSOFF	0x10000u /* qprocsoff() has been called */
#define	AM_CHNL_SIGNAL_NEEDED	0x20000u /* someone needs to send a signal */

/*
 * am_apm_persist_t	- audio mixer persistent private state data
 */
struct am_apm_persist {
	int		apm_mode;	/* mixer mode */
	int		apm_mpgain;	/* saved master play gain, mixer mode */
	int		apm_mpbal;	/* saved master play bal, mixer mode */
	int		apm_mrgain;	/* saved master rec. gain, mixer mode */
	int		apm_mrbal;	/* saved master rec. bal, mixer mode */
	uint_t		apm_pgain;	/* saved play gain */
	uint_t		apm_pbal;	/* saved play balance */
	uint_t		apm_pport;	/* saved play port */
	uint_t		apm_pmute;	/* saved output muted */
	uint_t		apm_rgain;	/* saved record gain */
	uint_t		apm_rbal;	/* saved record balance */
	uint_t		apm_rport;	/* saved record port */
	uint_t		apm_mgain;	/* saved monitor gain */
};
typedef struct am_apm_persist am_apm_persist_t;

_NOTE(SCHEME_PROTECTS_DATA("method", am_apm_persist::apm_mode))
_NOTE(SCHEME_PROTECTS_DATA("method", am_apm_persist::apm_mpgain))
_NOTE(SCHEME_PROTECTS_DATA("method", am_apm_persist::apm_mpbal))
_NOTE(SCHEME_PROTECTS_DATA("method", am_apm_persist::apm_mrgain))
_NOTE(SCHEME_PROTECTS_DATA("method", am_apm_persist::apm_mrbal))
_NOTE(SCHEME_PROTECTS_DATA("method", am_apm_persist::apm_pgain))
_NOTE(SCHEME_PROTECTS_DATA("method", am_apm_persist::apm_pbal))
_NOTE(SCHEME_PROTECTS_DATA("method", am_apm_persist::apm_pport))
_NOTE(SCHEME_PROTECTS_DATA("method", am_apm_persist::apm_pmute))
_NOTE(SCHEME_PROTECTS_DATA("method", am_apm_persist::apm_rgain))
_NOTE(SCHEME_PROTECTS_DATA("method", am_apm_persist::apm_rbal))
_NOTE(SCHEME_PROTECTS_DATA("method", am_apm_persist::apm_rport))
_NOTE(SCHEME_PROTECTS_DATA("method", am_apm_persist::apm_mgain))

/*
 * am_apm_private_t	- audio mixer state private data
 */
struct am_apm_private {
	kmutex_t		am_mode_lock;	/* lock for mode switch cv */
	kcondvar_t		am_mode_cv;	/* used to switch modes only */
	kmutex_t		am_ad_lock;	/* lock for calling driver */
	kcondvar_t		am_ad_cv;	/* serializes calls into drvr */
	int			am_ad_in;	/* set when calling driver */
	audio_info_t		am_hw_info;	/* pseudo hardware state */
	mblk_t			*am_sig_mp;	/* signal STREAMS message */
	audio_taskq_t		am_taskq;	/* h/w task queue */
	void			*am_args;	/* qtimeout() args */
	int			*am_mix_buf;	/* buffer to mix audio in */
	size_t			am_mix_size;	/* the size of the buffer */
	int			*am_send_buf;	/* buffer to send audio from */
	size_t			am_send_size;	/* the size of the buffer */
	uint_t			am_flags;	/* flags for the audio mixer */
	uint_t			am_pflags;	/* play flags for the mixer */
	uint_t			am_rflags;	/* record flags for the mixer */
	int			am_channels;	/* current channels */
	int			am_in_chs;	/* current record channels */
	int			am_out_chs;	/* current play channels */
	int			am_max_in_chs;	/* R/O, max input channels */
	int			am_max_out_chs;	/* R/O, max output channels */
	uint_t			am_hw_pchs;	/* the real h/w play channels */
	uint_t			am_hw_pprec;	/* the real h/w play prec. */
	uint_t			am_hw_penc;	/* the real h/w play encoding */
	uint_t			am_hw_rchs;	/* the real h/w rec. channels */
	uint_t			am_hw_rprec;	/* the real h/w rec. prec. */
	uint_t			am_hw_renc;	/* the real h/w rec. encoding */
	uint_t			am_save_psr;	/* saved play sample rate */
	uint_t			am_save_rsr;	/* saved record sample rate */
	uint_t			am_save_hw_rgain; /* saved h/w record gain */
	am_apm_persist_t	*am_pstate;	/* persistent state */
};
typedef struct am_apm_private am_apm_private_t;

/* defines for am_apm_private.am_ad_in */
#define	AM_APM_IN_DRIVER	0x00000001	/* mixer is calling driver */
#define	AM_APM_FREEZE		0x00000002	/* mixer can't call driver */
#define	AM_APM_FORCE		0x00000004	/* force driver calls */

_NOTE(MUTEX_PROTECTS_DATA(audio_apm_info::apm_lock, am_apm_private::am_flags))
_NOTE(MUTEX_PROTECTS_DATA(audio_apm_info::apm_lock,
    am_apm_private::am_send_size))
_NOTE(MUTEX_PROTECTS_DATA(audio_state::as_lock, am_apm_private::am_channels))
_NOTE(MUTEX_PROTECTS_DATA(audio_state::as_lock, am_apm_private::am_in_chs))
_NOTE(MUTEX_PROTECTS_DATA(audio_state::as_lock, am_apm_private::am_out_chs))
_NOTE(SCHEME_PROTECTS_DATA("method", am_apm_private::am_send_buf))

/*
 * These are modified only when the taskq lock is held, which ensures a
 * single thread.
 */
_NOTE(SCHEME_PROTECTS_DATA("method", am_apm_private::am_hw_info))
_NOTE(SCHEME_PROTECTS_DATA("method", am_apm_private::am_save_hw_rgain))

/*
 * Further analysis is needed on the structure members of am_apm_private.
 */
_NOTE(MUTEX_PROTECTS_DATA(am_apm_private::am_ad_lock, am_apm_private::am_ad_in))

_NOTE(READ_ONLY_DATA(am_apm_private::am_hw_pchs
	am_apm_private::am_hw_penc
	am_apm_private::am_hw_pprec
	am_apm_private::am_hw_rchs
	am_apm_private::am_hw_renc
	am_apm_private::am_hw_rprec))

/* am_apm_private.am_flags defines */
#define	AM_PRIV_ON_LINE		0x00000001u	/* device on line */
#define	AM_PRIV_SW_MODES	0x00000002u	/* switch between M & C mode */

/* am_apm_private.am_pflags and .am_rflags defines */
#define	AM_PRIV_CH_MONO		0x00000001u	/* mono supported */
#define	AM_PRIV_CH_STEREO	0x00000002u	/* stereo supported */
#define	AM_PRIV_16_PCM		0x00000004u	/* 16-bit PCM supported */
#define	AM_PRIV_8_PCM		0x00000008u	/* 8-bit PCM supported */
#define	AM_PRIV_8_ULAW		0x00000010u	/* 8-bit u-Law supported */
#define	AM_PRIV_8_ALAW		0x00000020u	/* 8-bit A-Law supported */
#define	AM_PRIV_16_TRANS	0x00000040u	/* do 16-bit unsigned trans */
#define	AM_PRIV_8_TRANS		0x00000080u	/* do 8-bit unsigned trans */

#define	AM_PRIV_TASKQ_NAME	"audio_mixer_taskq"	/* taskq name */

/*
 * The following data structures are used by taskq_dispatch() to queue up
 * ioctl() requests.
 */
struct am_ioctl_args {
	queue_t		*aia_q;			/* STREAMS queue */
	mblk_t		*aia_mp;		/* ioctl() message block */
};
typedef struct am_ioctl_args am_ioctl_args_t;

struct am_state_ch_args {
	audio_state_t	*asca_statep;		/* device state structure */
	audio_apm_info_t *asca_apm_infop;	/* mixer infop */
	int		asca_cmd;		/* hw state change command */
	int		asca_dir;		/* direction for the update */
	int		asca_value;		/* value for cmd to use */
};
typedef struct am_state_ch_args am_state_ch_args_t;

/*
 * Used only to execute a task off the taskq, so it is not shared.
 * am_sample_rates_t is defined in mixer.h.
 */
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", am_state_ch_args))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", am_sample_rates))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", am_ioctl_args))

/* steams stuff */
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", copyreq))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", copyresp))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", datab))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", iocblk))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", msgb))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", queue))

/* other unshared/stable or no lock needed stuff */
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", audio_channel))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", audio_i_state))
_NOTE(SCHEME_PROTECTS_DATA("method", audio_info))


/*
 * The following routines are provided by the different source code
 * modules that make up the audio mixer.
 *
 * From am_main.c
 */
int am_open_audio(queue_t *, dev_t *, int, int, cred_t *);
int am_open_audioctl(queue_t *, dev_t *, int, int, cred_t *);
int am_close_audio(queue_t *, int, cred_t *);
int am_close_audioctl(queue_t *, int, cred_t *);
int am_restore_state(audio_state_t *, audio_apm_info_t *, int);
int am_save_state(audio_state_t *, audio_apm_info_t *, int);
void am_apply_gain_balance(int *, int, int, int, int);
void am_convert_int_mono_stereo(int *, int *, int *, int, int);
void am_convert_to_int(void *, int *, int, int, int, int);
int am_reprocess(audio_ch_t *, audio_data_t *data);
void am_send_signal(audio_state_t *, am_apm_private_t *);
int am_update_conv_buffer(audio_ch_t *, size_t, int);
int am_update_src_buffer(audio_ch_t *, int, uint_t, int);

/*
 * From am_ad.c
 */
void am_ad_pause_play(audio_state_t *, am_apm_private_t *, am_ad_info_t *, int);
int am_ad_set_config(audio_state_t *, am_apm_private_t *, am_ad_info_t *, int,
    int, int, int, int, int);
int am_ad_set_format(audio_state_t *, am_apm_private_t *, am_ad_info_t *, int,
    int, int, int, int, int, int);
int am_ad_setup(audio_state_t *, am_apm_private_t *, am_ad_info_t *, int, int);
int am_ad_start_play(audio_state_t *, am_apm_private_t *, am_ad_info_t *, int,
    int);
int am_ad_start_record(audio_state_t *, am_apm_private_t *, am_ad_info_t *,
    int, int);
void am_ad_stop_play(audio_state_t *, am_apm_private_t *, am_ad_info_t *, int);
void am_ad_stop_record(audio_state_t *, am_apm_private_t *, am_ad_info_t *,
    int);
void am_ad_teardown(audio_state_t *, am_apm_private_t *, am_ad_info_t *, int,
    int);
int am_ck_channels(am_ad_ch_cap_t *, uint_t, boolean_t);
int am_ck_combinations(am_ad_cap_comb_t *, int, int, boolean_t);
int am_ck_sample_rate(am_ad_ch_cap_t *, int, int);
void am_safe_putnext(audio_ch_t *, mblk_t *);
int am_test_canputnext(audio_ch_t *);
int am_set_record_streams(audio_ch_t *);

/*
 * From am_ioctl.c
 */
int am_wiocdata(queue_t *, mblk_t *, audio_ch_t *);
int am_wioctl(queue_t *, mblk_t *, audio_ch_t *);
void am_audio_drained(audio_ch_t *);
int am_audio_set_info(audio_ch_t *, audio_info_t *, audio_info_t *);
int am_set_format(audio_state_t *, am_apm_private_t *, am_ad_info_t *, int,
    int, int, int, int, int, int, int);
int am_set_gain(audio_state_t *, audio_apm_info_t *, uint_t, uint_t,
    uint_t, int, int, int, int);

/*
 * From g711.h
 */
extern int16_t _8alaw2linear16[256];
extern int8_t _8alaw2linear8[256];
extern int16_t _8ulaw2linear16[256];
extern int8_t _8ulaw2linear8[256];
extern uint8_t _13linear2alaw8[0x2000];
extern uint8_t _14linear2ulaw8[0x4000];

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AUDIO_MIXER_IMPL_H */
