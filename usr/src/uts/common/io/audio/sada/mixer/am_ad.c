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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains the code that the Audio Driver calls into and the
 * private routines that support these calls.
 *
 * NOTE: When allocating conversion buffers for recording we have to be
 *	careful that the recording device isn't mono. Otherwise we won't
 *	have enough memory for converting.
 *
 * These entry points are defined in audio_mixer.h:
 *	am_attach()
 *	am_detach()
 *	am_get_audio()
 *	am_play_shutdown()
 *	am_send_audio()
 *	am_hw_state_change()
 *	am_get_src_data()
 *	am_set_src_data()
 *
 * These additional functions are also provided:
 *	am_ad_pause_play()
 *	am_ad_set_config()
 *	am_ad_set_format()
 *	am_ad_setup()
 *	am_ad_start_play()
 *	am_ad_start_record()
 *	am_ad_stop_play()
 *	am_ad_stop_record()
 *	am_ad_teadown()
 *	am_ck_channels()
 *	am_ck_combinations()
 *	am_ck_sample_rate()
 *	am_safe_putnext()
 *	am_test_canputnext()
 */

#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/stropts.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/note.h>
#include <sys/audio.h>
#include <sys/audiovar.h>
#include <sys/audio/audio_support.h>
#include <sys/audio/audio_apm.h>
#include <sys/audio/audio_src.h>
#include <sys/audio/audio_trace.h>
#include <sys/audio/g711.h>
#include <sys/mixer.h>
#include <sys/audio/audio_mixer.h>
#include <sys/audio/impl/audio_mixer_impl.h>

/*
 * Local routine prototypes used only by this file.
 */
static int am_attach_check(audio_state_t *,
	am_ad_info_t *, am_apm_private_t *, int);
static int am_ck_sample_rate_sanity(am_ad_ch_cap_t *, int);
static void am_convert_to_format(int *, void *, int, int, int, int);
static int am_get_audio_multi(audio_state_t *, void *, int, int);
static int am_get_audio_trad_compat(audio_state_t *, audio_apm_info_t *,
	void *, int);
static int am_get_audio_trad_mixer(audio_state_t *, audio_apm_info_t *,
	void *, int);
static int am_get_samples(audio_ch_t *, int, void *, int);
static void am_play_shutdown_multi(audiohdl_t, int);
static void am_play_shutdown_trad(audiohdl_t, audio_apm_info_t *);
static void am_release_ad_access(am_apm_private_t *);
static void am_send_audio_common(audio_ch_t *, void *, int);
static void am_send_audio_multi(audio_state_t *, am_ad_info_t *, void *,
	int, int);
static void am_send_audio_trad_compat(audio_state_t *, audio_apm_info_t *,
	int *, int);
static void am_send_audio_trad_mixer(audio_state_t *, audio_apm_info_t *,
	int *, const int);
static void am_serialize_ad_access(am_apm_private_t *);

/*
 * Taskq callbacks.
 */
static void am_hw_task(void *);

/*
 * Module global hidden variables
 */
static audio_device_t mixer_device_info = {
	MIXER_NAME,
	MIXER_VERSION,
	MIXER_CONFIGURATION
};

static int mixer_bufsize = AM_DEFAULT_MIX_BUFSIZE;

/* XXX this is a lie */
_NOTE(SCHEME_PROTECTS_DATA("this is a lie", mixer_bufsize))

/*
 * The main routines for this file. These are the Audio Driver entry points.
 */

/*
 * am_attach()
 *
 * TODO:	Check for PLINK
 *
 * Description:
 *	Attach an instance of the mixer. We initialize all the data structures
 *	and register the APM for both AUDIO and AUDIOCTL. Two audio_apm_info
 *	data structures are created, however they share the same private data
 *	structure.
 *
 *	We check both MIXER and COMPAT modes because we can switch between
 *	them and thus we need to make sure everything is okay for both modes.
 *	Plus we need the initial condition for both modes to support switching.
 *
 *	NOTE: mutex_init() and cv_init() no longer needs a name string, so set
 *	      to NULL to save kernel space.
 *
 *	NOTE: It is okay for memory allocation to sleep.
 *
 * Arguments:
 *	audiohdl_t	handle		Handle to the device
 *	ddi_attach_cmd_t cmd		Attach command
 *	am_ad_info_t	*ad_infop	Ptr to the device's capabilities struct
 *
 * Returns:
 *	AUDIO_SUCCESS		If the mixer was initialized properly
 *	AUDIO_FAILURE		If the mixer couldn't be initialized properly
 */
int
am_attach(audiohdl_t handle, ddi_attach_cmd_t cmd, am_ad_info_t *ad_infop)
{
	audio_state_t		*statep = AUDIO_HDL2STATE(handle);
	audio_info_t		*hw_info;
	audio_apm_info_t	*apm_infop1;
	audio_apm_info_t	*apm_infop2;
	am_apm_persist_t	*persistp;
	am_apm_private_t	*stpptr;
	audio_apm_reg_t		reg_info;
	minor_t			minor;
	int			mpgain = 0;
	int			mpbal = 0;
	int			mrgain = 0;
	int			mrbal = 0;
	uint_t			mgain = 0;
	uint_t			pbalance = AUDIO_MID_BALANCE;
	uint_t			pgain = 0;
	uint_t			rbalance = AUDIO_MID_BALANCE;
	uint_t			rgain = 0;
	int			doread;		/* device supports record */
	int			dowrite;	/* device supports play */
	int			mode;
	int			psr;
	int			rsr;

	ATRACE("in am_attach()", ad_infop);
	ASSERT(statep);

	switch (cmd) {
	case DDI_ATTACH:
		break;
	default:
		ATRACE_32("am_attach() unknown command failure", cmd);
		return (AUDIO_FAILURE);
	}

	/* before we do anything else make sure the interface versions are ok */
	if (ad_infop->ad_int_vers != AM_VERSION) {
		ATRACE_32("am_attach() unsupported interface versions",
		    ad_infop->ad_int_vers);
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN,
		    "am_attach() interface version not supported: %d",
		    ad_infop->ad_int_vers);
		return (AUDIO_FAILURE);
	}

	/* get the properties from the .conf file */
	if ((mixer_bufsize = ddi_prop_get_int(DDI_DEV_T_ANY, statep->as_dip,
	    DDI_PROP_DONTPASS, "mixer_bufsize", AM_DEFAULT_MIX_BUFSIZE)) ==
	    AM_DEFAULT_MIX_BUFSIZE) {
		ATRACE_32("am_attach() setting mix buffer size",
		    AM_DEFAULT_MIX_BUFSIZE);
#ifdef DEBUG
	} else {
		ATRACE_32("am_attach() setting mix buffer size from .conf",
		    mixer_bufsize);
#else
		/*EMPTY*/
#endif
	}
	if (mixer_bufsize < AM_DEFAULT_MIX_BUFSIZE) {
		ATRACE_32("am_attach() mix buffer too small", mixer_bufsize);
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN, "am_attach() "
		    "ddi_prop_get_int() mix buffer too small, setting to %d",
		    AM_DEFAULT_MIX_BUFSIZE);
		mixer_bufsize = AM_DEFAULT_MIX_BUFSIZE;
		ATRACE_32("am_attach() setting new mix buffer size",
		    mixer_bufsize);
	}

	/* figure out the direction and sanity check */
	doread = ad_infop->ad_defaults->hw_features & AUDIO_HWFEATURE_RECORD;
	dowrite = ad_infop->ad_defaults->hw_features & AUDIO_HWFEATURE_PLAY;
	if (!doread && !dowrite) {
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN,
		    "am_attach() audio device doesn't play or record");
		return (AUDIO_FAILURE);
	}
	ATRACE_32("am_attach() doread", doread);
	ATRACE_32("am_attach() dowrite", dowrite);

	/* check the sample rate converter */
	if (ad_infop->ad_codec_type == AM_TRAD_CODEC) {
		/* make sure the version is okay */
		if (dowrite &&
		    ad_infop->ad_play.ad_conv->ad_version != AM_SRC_VERSION) {
			audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN,
			    "am_attach() bad play src version: %d",
			    ad_infop->ad_play.ad_conv->ad_version);
			return (AUDIO_FAILURE);
		}
		if (doread &&
		    ad_infop->ad_record.ad_conv->ad_version != AM_SRC_VERSION) {
			audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN,
			    "am_attach() bad record src version: %d",
			    ad_infop->ad_record.ad_conv->ad_version);
			return (AUDIO_FAILURE);
		}
	}

	/* get the state pointer for this instance */
	if ((statep = audio_sup_devinfo_to_state(statep->as_dip)) == NULL) {
		ATRACE("am_attach() couldn't get state structure", 0);
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN,
		    "am_attach() couldn't get state structure");
		return (AUDIO_FAILURE);
	}

	/* allocate the audio mixer private data */
	stpptr = kmem_zalloc(sizeof (*stpptr), KM_SLEEP);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*stpptr));

	hw_info = &stpptr->am_hw_info;

	/* make sure we won't free the device state structure */
	hw_info->ref_cnt = 1;

	/* we assume the device is on line when we attach */
	stpptr->am_flags |= AM_PRIV_ON_LINE;

	/* initialize mutexes and cvs */
	mutex_init(&stpptr->am_mode_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&stpptr->am_ad_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&stpptr->am_mode_cv, NULL, CV_DRIVER, NULL);
	cv_init(&stpptr->am_ad_cv, NULL, CV_DRIVER, NULL);

	/*
	 * WARNING: From here on all error returns must be through one
	 *	of the error_? labels. Otherwise we'll have a memory leak.
	 */

	/* start off with allocating the signal message buffer */
	if ((stpptr->am_sig_mp = allocb(sizeof (int8_t), BPRI_HI)) == NULL) {
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
		    "attach() couldn't allocate message block to send signal");
		goto error_free_private;
	}
	ASSERT(stpptr->am_sig_mp->b_cont == 0);
	/* turn it into a signal */
	stpptr->am_sig_mp->b_datap->db_type = M_PCSIG;
	*stpptr->am_sig_mp->b_wptr++ = SIGPOLL;

	/* register the mixer with the Audio Support Module */
	reg_info.aar_version =		AM_AAR_VERSION;
	reg_info.aar_apm_open =		am_open_audio;
	reg_info.aar_apm_close =	am_close_audio;
	reg_info.aar_apm_save_state =	am_save_state;
	reg_info.aar_apm_restore_state = am_restore_state;
	reg_info.aar_private =		stpptr;
	reg_info.aar_info =		ad_infop;
	reg_info.aar_state =		hw_info;
	reg_info.aar_dev_info =		&mixer_device_info;

	if ((apm_infop1 = audio_sup_register_apm(statep, AUDIO,
	    &reg_info)) == NULL) {
		ATRACE_32("am_attach() couldn't register AUDIO", 0);
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN, "am_attach() "
		    "couldn't register the AUDIO device with audiosup");
		goto error_free_msg;
	}

	reg_info.aar_apm_open =		am_open_audioctl;
	reg_info.aar_apm_close =	am_close_audioctl;
	reg_info.aar_apm_save_state =	NULL;
	reg_info.aar_apm_restore_state = NULL;

	if ((apm_infop2 = audio_sup_register_apm(statep, AUDIOCTL,
	    &reg_info)) == NULL) {
		ATRACE_32("am_attach() couldn't register AUDIOCTL", 0);
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN, "am_attach() "
		    "couldn't register the AUDIOCTL device with audiosup");
		goto error_unregister;
	}

	/* set the max input and output channels, making sure they are sane */
	if (ad_infop->ad_record.ad_max_chs > statep->as_max_chs) {
		stpptr->am_max_in_chs = statep->as_max_chs;
	} else {
		stpptr->am_max_in_chs = ad_infop->ad_record.ad_max_chs;
	}
	if (ad_infop->ad_play.ad_max_chs > statep->as_max_chs) {
		stpptr->am_max_out_chs = statep->as_max_chs;
	} else {
		stpptr->am_max_out_chs = ad_infop->ad_play.ad_max_chs;
	}
	ATRACE_32("am_attach() am_max_in_chs", stpptr->am_max_in_chs);
	ATRACE_32("am_attach() am_max_out_chs", stpptr->am_max_out_chs);

	/* get the persistent state, if not there then first time so allocate */
	persistp = audio_sup_get_persist_state(statep, AUDIO);
	if (persistp == NULL) {
		ATRACE("am_attach() 1st time persist or reset state", persistp);

		/* allocate the structure and save */
		persistp = kmem_alloc(sizeof (*persistp), KM_SLEEP);
		if (audio_sup_set_persist_state(statep, AUDIO,
		    persistp, sizeof (*persistp)) == AUDIO_FAILURE) {
			ATRACE("am_attach() cannot set persist", 0)
			goto error_unregister;
		}

		/* get the mode from the driver */
		mode = ad_infop->ad_mode;

		/* and also get the monitor gain */
		mgain = ad_infop->ad_defaults->monitor_gain;

		/* get the gains from the drive, based on mode */
		if (mode == AM_MIXER_MODE &&
		    ad_infop->ad_codec_type == AM_TRAD_CODEC) {
			if (dowrite) {
				pgain = AM_DEFAULT_MIXER_GAIN;
				pbalance = AUDIO_MID_BALANCE;
				mpgain = pgain;
				mpbal = pbalance;
			}
			if (doread) {
				rgain = AUDIO_MID_GAIN;
				rbalance = AUDIO_MID_BALANCE;
				mrgain = rgain;
				mrbal = rbalance;
			}
		} else {
			if (dowrite) {
				pgain = ad_infop->ad_defaults->play.gain;
				pbalance = ad_infop->ad_defaults->play.balance;
			}
			if (doread) {
				rgain = ad_infop->ad_defaults->record.gain;
				rbalance =
				    ad_infop->ad_defaults->record.balance;
			}
		}

		persistp->apm_mpgain = pgain;
		persistp->apm_mpbal = pbalance;
		persistp->apm_mrgain = rgain;
		persistp->apm_mrbal = rbalance;
		persistp->apm_mode = mode;
		persistp->apm_pgain = pgain;
		persistp->apm_pbal = pbalance;
		persistp->apm_rgain = rgain;
		persistp->apm_rbal = rbalance;
		persistp->apm_mgain = mgain;

		if (dowrite) {
			ad_infop->ad_defaults->play.port |=
			    ad_infop->ad_defaults->play.avail_ports ^
			    ad_infop->ad_defaults->play.mod_ports;
		}
		if (doread) {
			ad_infop->ad_defaults->record.port |=
			    ad_infop->ad_defaults->record.avail_ports ^
			    ad_infop->ad_defaults->record.mod_ports;
		}
	} else {
		/* the mode comes from the peristent data */
		mode = persistp->apm_mode;
		mpgain = persistp->apm_mpgain;
		mpbal = persistp->apm_mpbal;
		mrgain = persistp->apm_mrgain;
		mrbal = persistp->apm_mrbal;
		pgain = persistp->apm_pgain;
		pbalance = persistp->apm_pbal;
		ad_infop->ad_defaults->play.port = persistp->apm_pport;
		ad_infop->ad_defaults->output_muted = persistp->apm_pmute;
		rgain = persistp->apm_rgain;
		rbalance = persistp->apm_rbal;
		mgain = persistp->apm_mgain;
		ad_infop->ad_defaults->record.port = persistp->apm_rport;
	}

	/* save persistent state in private data structure */
	stpptr->am_pstate = persistp;

	/*
	 * CAUTION: Keep the calls in am_restore_state() the same as in
	 *	this routine. There may be order dependencies and once the
	 *	audio driver works we don't want to break it if we change
	 *	the order.
	 *
	 * Check the write capabilities, if the device supports it.
	 */
	ASSERT(stpptr->am_pflags == NULL);
	ASSERT(stpptr->am_rflags == NULL);
	if (dowrite) {
		if (am_attach_check(statep, ad_infop, stpptr, AUDIO_PLAY) ==
		    AUDIO_FAILURE) {
			ATRACE("am_attach() am_attach_check() failed", 0);
			goto error_unregister_both;
		}

		/* get initial conditions */
		if (mode == AM_MIXER_MODE &&
		    ad_infop->ad_codec_type == AM_TRAD_CODEC) {
			psr = stpptr->am_save_psr;
		} else {
			psr = ad_infop->ad_defaults->play.sample_rate;
		}

		/* see if we need to translate to unsigned */
		if (ad_infop->ad_translate_flags & AM_MISC_16_P_TRANSLATE) {
			stpptr->am_pflags |= AM_PRIV_16_TRANS;
		}
		if (ad_infop->ad_translate_flags & AM_MISC_8_P_TRANSLATE) {
			stpptr->am_pflags |= AM_PRIV_8_TRANS;
		}

		/* now that we've got the h/w info we set the initial format */
		if (am_set_format(statep, stpptr, ad_infop, AM_SET_CONFIG_BOARD,
		    AUDIO_PLAY, psr, stpptr->am_hw_pchs, stpptr->am_hw_pprec,
		    stpptr->am_hw_penc, AM_NO_FORCE, AM_NO_SERIALIZE) ==
		    AUDIO_FAILURE) {
			audio_sup_log(AUDIO_STATE2HDL(statep),
			    CE_WARN, "am_attach() "
			    "couldn't set play data format: %d %d %d %d",
			    psr, stpptr->am_hw_pchs, stpptr->am_hw_pprec,
			    stpptr->am_hw_penc);
			goto error_unregister_both;
		}

		if (mode == AM_MIXER_MODE &&
		    ad_infop->ad_codec_type == AM_TRAD_CODEC) {
			if (am_set_gain(statep, apm_infop1,
			    hw_info->play.channels, mpgain, mpbal, AUDIO_PLAY,
			    AM_SET_CONFIG_BOARD, AM_NO_FORCE,
			    AM_NO_SERIALIZE) == AUDIO_FAILURE) {
				audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN,
				    "am_attach() couldn't set mixer play gain");
				goto error_unregister_both;
			}
		} else {
			if (am_set_gain(statep, apm_infop1,
			    hw_info->play.channels, pgain, pbalance, AUDIO_PLAY,
			    AM_SET_CONFIG_BOARD, AM_NO_FORCE,
			    AM_NO_SERIALIZE) == AUDIO_FAILURE) {
				audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN,
				    "am_attach() "
				    "couldn't set compat play gain");
				goto error_unregister_both;
			}
		}
	} else {
		ASSERT(hw_info->play.sample_rate == 0);
		pgain = AUDIO_MIN_GAIN;
		pbalance = AUDIO_MID_BALANCE;
	}
	hw_info->play.gain = pgain;
	hw_info->play.balance = pbalance;

	/* now check the read capabilities, if the device supports it */
	if (doread) {
		if (am_attach_check(statep, ad_infop, stpptr, AUDIO_RECORD) ==
		    AUDIO_FAILURE) {
			ATRACE("am_attach() am_attach_check() failed", 0);
			goto error_unregister_both;
		}

		/* get initial conditions */
		if (mode == AM_MIXER_MODE &&
		    ad_infop->ad_codec_type == AM_TRAD_CODEC) {
			rsr = stpptr->am_save_rsr;
		} else {
			rsr = ad_infop->ad_defaults->record.sample_rate;
		}

		/* see if we need to translate to unsigned */
		if (ad_infop->ad_translate_flags & AM_MISC_16_R_TRANSLATE) {
			stpptr->am_rflags |= AM_PRIV_16_TRANS;
		}
		if (ad_infop->ad_translate_flags & AM_MISC_8_R_TRANSLATE) {
			stpptr->am_rflags |= AM_PRIV_8_TRANS;
		}

		/* now that we've got the h/w info we set the initial format */
		if (am_set_format(statep, stpptr, ad_infop, AM_SET_CONFIG_BOARD,
		    AUDIO_RECORD, rsr, stpptr->am_hw_rchs, stpptr->am_hw_rprec,
		    stpptr->am_hw_renc, AM_NO_FORCE, AM_NO_SERIALIZE) ==
		    AUDIO_FAILURE) {
			audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN,
			    "am_attach() "
			    "couldn't set record data format: %d %d %d %d",
			    rsr, stpptr->am_hw_rchs, stpptr->am_hw_rprec,
			    stpptr->am_hw_renc);
			goto error_unregister_both;
		}

		/* set the gains */
		if (mode == AM_MIXER_MODE &&
		    ad_infop->ad_codec_type == AM_TRAD_CODEC) {
			if (am_set_gain(statep, apm_infop1,
			    hw_info->record.channels, mrgain, mrbal,
			    AUDIO_RECORD, AM_SET_CONFIG_BOARD, AM_NO_FORCE,
			    AM_NO_SERIALIZE) == AUDIO_FAILURE) {
				audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN,
				    "am_attach() "
				    "couldn't set mixer record gain");
				goto error_unregister_both;
			}
		} else {
			if (am_set_gain(statep, apm_infop1,
			    hw_info->record.channels, rgain, rbalance,
			    AUDIO_RECORD, AM_SET_CONFIG_BOARD, AM_NO_FORCE,
			    AM_NO_SERIALIZE) == AUDIO_FAILURE) {
				audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN,
				    "am_attach() "
				    "couldn't set compat record gain");
				goto error_unregister_both;
			}
		}
	} else {
		ASSERT(hw_info->record.sample_rate == 0);
		rgain = AUDIO_MIN_GAIN;
		rbalance = AUDIO_MID_BALANCE;
	}
	hw_info->record.gain = rgain;
	hw_info->record.balance = rbalance;

	/* starting point for unmute */
	stpptr->am_save_hw_rgain = AUDIO_MID_GAIN;

	/*
	 * Allocate mix and send buffers, but only if TRAD Codec and doing
	 * this direction.
	 */
	ASSERT(stpptr->am_mix_size == 0);
	ASSERT(stpptr->am_mix_buf == NULL);
	ASSERT(stpptr->am_send_size == 0);
	ASSERT(stpptr->am_send_buf == NULL);
	if (ad_infop->ad_codec_type == AM_TRAD_CODEC) {
		/* allocate the mix buffer */
		if (dowrite) {
			stpptr->am_mix_buf = kmem_alloc(mixer_bufsize,
			    KM_SLEEP);
			stpptr->am_mix_size = mixer_bufsize;
		}

		/* allocate the send buffer */
		if (doread) {
			stpptr->am_send_buf = kmem_alloc(mixer_bufsize,
			    KM_SLEEP);
			stpptr->am_send_size = mixer_bufsize;
		}
	}

	/* create the devices for successive open()'s to clone off of */
	if ((minor = audio_sup_type_to_minor(AUDIO)) == AUDIO_FAILURE) {
		ATRACE("am_attach() sound,audio get minor failure", minor);
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN,
		    "am_attach() create audio minor node failure");
		goto error_unregister_both;
	}
	minor += statep->as_dev_instance *
		audio_sup_get_minors_per_inst(AUDIO_STATE2HDL(statep));
	if (ddi_create_minor_node(statep->as_dip, "sound,audio", S_IFCHR,
	    minor, DDI_NT_AUDIO, 0) == DDI_FAILURE) {
		ATRACE("am_attach() sound,audio minor dev failure", 0);
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN,
		    "am_attach() create audio minor node failure");
		goto error_unregister_both;
	}

	if ((minor = audio_sup_type_to_minor(AUDIOCTL)) == AUDIO_FAILURE) {
		ATRACE("am_attach() sound,audioctl get minor failure", minor);
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN,
		    "am_attach() create audioctl minor node failure");
		goto error_rem_minor;
	}
	minor += statep->as_dev_instance *
		audio_sup_get_minors_per_inst(AUDIO_STATE2HDL(statep));
	if (ddi_create_minor_node(statep->as_dip, "sound,audioctl", S_IFCHR,
	    minor, DDI_NT_AUDIO, 0) == DDI_FAILURE) {
		ATRACE("am_attach() sound,audioctl minor dev failure", 0);
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN,
		    "am_attach() create audioctl minor node failure");
		goto error_rem_minor;
	}

	ASSERT(hw_info->play.port == 0);
	ASSERT(hw_info->play.avail_ports == 0);
	ASSERT(hw_info->play.mod_ports == 0);
	/* turn on in the state structure those ports that will always be on */
	if (dowrite) {
		if (am_ad_set_config(statep, stpptr, ad_infop,
		    AM_SET_CONFIG_BOARD, AM_SET_PORT, AUDIO_PLAY,
		    ad_infop->ad_defaults->play.port, NULL,
		    AM_NO_SERIALIZE) == AUDIO_FAILURE) {
			audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN,
			    "am_attach() couldn't set play port: 0x%x",
			    ad_infop->ad_defaults->play.port);
			goto error_rem_minor;
		} else {
			hw_info->play.port =
			    ad_infop->ad_defaults->play.port;
			hw_info->play.avail_ports =
			    ad_infop->ad_defaults->play.avail_ports;
			hw_info->play.mod_ports =
			    ad_infop->ad_defaults->play.mod_ports;
		}
	}
	ASSERT(hw_info->record.port == 0);
	ASSERT(hw_info->record.avail_ports == 0);
	ASSERT(hw_info->record.mod_ports == 0);
	/* turn on in the state structure those ports that will always be on */
	if (doread) {
		if (am_ad_set_config(statep, stpptr, ad_infop,
		    AM_SET_CONFIG_BOARD, AM_SET_PORT, AUDIO_RECORD,
		    ad_infop->ad_defaults->record.port, NULL,
		    AM_NO_SERIALIZE) == AUDIO_FAILURE) {
			audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN,
			    "am_attach() couldn't set record port: 0x%x",
			    ad_infop->ad_defaults->record.port);
			goto error_rem_minor;
		} else {
			hw_info->record.port =
			    ad_infop->ad_defaults->record.port;
			hw_info->record.avail_ports =
			    ad_infop->ad_defaults->record.avail_ports;
			hw_info->record.mod_ports =
			    ad_infop->ad_defaults->record.mod_ports;
		}
	}

	if ((ad_infop->ad_defaults->hw_features & AUDIO_HWFEATURE_IN2OUT) &&
	    am_ad_set_config(statep, stpptr, ad_infop, AM_SET_CONFIG_BOARD,
	    AM_SET_MONITOR_GAIN, AUDIO_BOTH, mgain, NULL, AM_NO_SERIALIZE) ==
	    AUDIO_FAILURE) {
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN,
		    "am_attach() couldn't set monitor gain: 0x%x", mgain);
		goto error_rem_minor;
	}

	if (dowrite && am_ad_set_config(statep, stpptr, ad_infop,
	    AM_SET_CONFIG_BOARD, AM_OUTPUT_MUTE, AUDIO_PLAY,
	    ad_infop->ad_defaults->output_muted, NULL, AM_NO_SERIALIZE) ==
	    AUDIO_FAILURE) {
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN,
		    "am_attach() couldn't set output muted: 0x%x",
		    ad_infop->ad_defaults->output_muted);
		goto error_rem_minor;
	}

	if (doread && (ad_infop->ad_assist_flags & AM_ASSIST_MIC) &&
	    am_ad_set_config(statep, stpptr, ad_infop, AM_SET_CONFIG_BOARD,
	    AM_MIC_BOOST, AUDIO_RECORD,
	    (ad_infop->ad_add_mode & AM_ADD_MODE_MIC_BOOST), NULL,
	    AM_NO_SERIALIZE) == AUDIO_FAILURE) {
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN,
		    "am_attach() couldn't set mic boost: 0x%x",
		    ad_infop->ad_add_mode);
		goto error_rem_minor;
	}

	/* set misc hardware state */
	if (dowrite) {
		hw_info->play.buffer_size =
		    ad_infop->ad_defaults->play.buffer_size;
	} else {
		hw_info->play.buffer_size = 0;
	}
	ASSERT(hw_info->play.samples == 0);
	ASSERT(hw_info->play.eof == 0);
	ASSERT(hw_info->play.pause == 0);
	ASSERT(hw_info->play.error == 0);
	ASSERT(hw_info->play.waiting == 0);
	ASSERT(hw_info->play.minordev == 0);
	ASSERT(hw_info->play.open == 0);
	ASSERT(hw_info->play.active == 0);
	if (doread) {
		hw_info->record.buffer_size =
		    ad_infop->ad_defaults->record.buffer_size;
	} else {
		hw_info->record.buffer_size = 0;
	}
	ASSERT(hw_info->record.samples == 0);
	ASSERT(hw_info->record.eof == 0);
	ASSERT(hw_info->record.pause == 0);
	ASSERT(hw_info->record.error == 0);
	ASSERT(hw_info->record.waiting == 0);
	ASSERT(hw_info->record.minordev == 0);
	ASSERT(hw_info->record.open == 0);
	ASSERT(hw_info->record.active == 0);

	hw_info->monitor_gain = mgain;
	hw_info->output_muted = ad_infop->ad_defaults->output_muted;
	hw_info->hw_features = ad_infop->ad_defaults->hw_features;
	hw_info->sw_features = ad_infop->ad_defaults->sw_features;

	if (mode == AM_MIXER_MODE) {
		hw_info->sw_features_enabled = AUDIO_SWFEATURE_MIXER;
	} else {
		hw_info->sw_features_enabled = 0;
	}

	/* create a single threaded task queue, this always succeeds */
	stpptr->am_taskq = audio_sup_taskq_create(AM_PRIV_TASKQ_NAME);
	if (stpptr->am_taskq == NULL) {
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN,
		    "am_attach() couldn't create the taskq, out of memory");
		goto error_rem_minor;
	}

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*stpptr));

	ATRACE_32("am_attach() returning", statep->as_dev_instance);

	return (AUDIO_SUCCESS);

error_rem_minor:
	ATRACE("am_attach() failure, removing minor nodes", 0);
	/*
	 * We don't use NULL because other APMs may own other minor devices
	 * and we don't want to remove them from under them.
	 */
	ddi_remove_minor_node(statep->as_dip, "sound,audio");
	ddi_remove_minor_node(statep->as_dip, "sound,audioctl");

error_unregister_both:
	mutex_enter(&apm_infop2->apm_lock);
	apm_infop2->apm_private = NULL;
	mutex_exit(&apm_infop2->apm_lock);
	if (audio_sup_unregister_apm(statep, AUDIOCTL) == AUDIO_FAILURE) {
		ATRACE_32("am_attach() audio_sup_unregister_apm() "
		    "AUDIOCTL failed", statep->as_dev_instance);
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN,
		    "am_attach() audio_sup_unregister_apm() "
		    "AUDIOCTL failed");
	}

error_unregister:
	mutex_enter(&apm_infop1->apm_lock);
	apm_infop1->apm_private = NULL;
	mutex_exit(&apm_infop1->apm_lock);
	if (audio_sup_unregister_apm(statep, AUDIO) == AUDIO_FAILURE) {
		ATRACE_32("am_attach() audio_sup_unregister_apm() "
		    "AUDIO failed", statep->as_dev_instance);
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN,
		    "am_attach() audio_sup_unregister_apm() "
		    "AUDIO failed");
	}

error_free_msg:
	freemsg(stpptr->am_sig_mp);

error_free_private:
	/* destroy mutexes and cvs */
	mutex_destroy(&stpptr->am_mode_lock);
	mutex_destroy(&stpptr->am_ad_lock);
	cv_destroy(&stpptr->am_mode_cv);
	cv_destroy(&stpptr->am_ad_cv);

	ATRACE("am_attach() failure, freeing private structure", 0);
	if (stpptr->am_mix_buf) {
		kmem_free(stpptr->am_mix_buf, stpptr->am_mix_size);
	}
	if (stpptr->am_send_buf) {
		kmem_free(stpptr->am_send_buf, stpptr->am_send_size);
	}
	kmem_free(stpptr, sizeof (*stpptr));

fail:
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*stpptr));
	ATRACE("am_attach() returning failure", 0);

	return (AUDIO_FAILURE);

}	/* am_attach() */

/*
 * am_detach()
 *
 * Description:
 *	Detach an instance of the mixer. Free up all data structures and
 *	unregister the APM for both AUDIO and AUDIOCTL. We also remove
 *	the device nodes. However it is possible another APM may still be
 *	attached, so we are careful to only remove the audio and audioctl
 *	devices.
 *
 *	NOTE: This routine will never be called in the audio device
 *		has any channels in use, so we don't need to check
 *		for this.
 *
 *
 * Arguments:
 *	audiohdl_t	handle	Handle to the device
 *	ddi_detach_cmd_t cmd	Detach command
 *
 * Returns:
 *	AUDIO_SUCCESS		If the mixer was detached
 *	AUDIO_FAILURE		If the mixer couldn't be detached
 */
int
am_detach(audiohdl_t handle, ddi_detach_cmd_t cmd)
{
	audio_state_t		*statep = AUDIO_HDL2STATE(handle);
	audio_apm_info_t	*apm_infop1;
	audio_apm_info_t	*apm_infop2;
	am_apm_private_t	*stpptr;
	am_apm_persist_t	*persistp;
	audio_info_t		*hw_info;

	ATRACE_32("in am_detach()", cmd);
	ATRACE("am_detach() handle", handle);
	ASSERT(statep);

	switch (cmd) {
	case DDI_DETACH:
		break;
	default:
		ATRACE_32("am_detach() unknown command failure", cmd);
		return (AUDIO_FAILURE);
	}

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*stpptr));

	/*
	 * Remove only the AUDIO and AUDIOCTL minor nodes for this
	 * dev_info. We don't want to free the nodes other APMs are
	 * responsible for.
	 */
	ddi_remove_minor_node(statep->as_dip, "sound,audio");
	ddi_remove_minor_node(statep->as_dip, "sound,audioctl");

	/* get rid of the private data structure */
	if ((apm_infop1 = audio_sup_get_apm_info(statep, AUDIO)) == NULL) {
		ATRACE("am_detach() audio_sup_get_apm_info() AUDIO failed",
		    statep);
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
		    "detach() audio_sup_get_apm_info() AUDIO failed");

		goto fail;
	}
	if ((apm_infop2 =
	    audio_sup_get_apm_info(statep, AUDIOCTL)) == NULL) {
		ATRACE("am_detach() audio_sup_get_apm_info() AUDIOCTL failed",
		    statep);
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
		    "detach() audio_sup_get_apm_info() AUDIOCTL failed");

		goto fail;
	}
	/*
	 * Both apm_info pointers use the same apm_private structure, so we
	 * only need to clear it once.
	 */
	stpptr = apm_infop1->apm_private;
	ASSERT(stpptr->am_channels == 0);
	ASSERT(stpptr->am_in_chs == 0);
	ASSERT(stpptr->am_out_chs == 0);

	/* save the current h/w state in persistent memory */
	hw_info = &stpptr->am_hw_info;
	persistp = stpptr->am_pstate;
	if (persistp->apm_mode == AM_MIXER_MODE) {
		persistp->apm_mpgain = hw_info->play.gain;
		persistp->apm_mpbal = hw_info->play.balance;
		persistp->apm_mrgain = hw_info->record.gain;
		persistp->apm_mrbal = hw_info->record.balance;
	}
	persistp->apm_pgain = hw_info->play.gain;
	persistp->apm_pbal = hw_info->play.balance;
	persistp->apm_pport = hw_info->play.port;
	persistp->apm_pmute = hw_info->output_muted;
	persistp->apm_rgain = hw_info->record.gain;
	persistp->apm_rbal = hw_info->record.balance;
	persistp->apm_rport = hw_info->record.port;
	persistp->apm_mgain = hw_info->monitor_gain;

	/* wait for the taskq to empty and then destroy it */
	audio_sup_taskq_wait(stpptr->am_taskq);
	audio_sup_taskq_destroy(stpptr->am_taskq);

	/* destroy mutexes and cvs */
	mutex_destroy(&stpptr->am_mode_lock);
	mutex_destroy(&stpptr->am_ad_lock);
	cv_destroy(&stpptr->am_mode_cv);
	cv_destroy(&stpptr->am_ad_cv);

	ASSERT(stpptr->am_sig_mp);
	freemsg(stpptr->am_sig_mp);

	if (stpptr->am_mix_buf) {
		ASSERT(stpptr->am_mix_size);
		kmem_free(stpptr->am_mix_buf, stpptr->am_mix_size);
	}
	if (stpptr->am_send_buf) {
		ASSERT(stpptr->am_send_size);
		kmem_free(stpptr->am_send_buf, stpptr->am_send_size);
	}
	kmem_free(stpptr, sizeof (*stpptr));
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*stpptr));

	mutex_enter(&apm_infop1->apm_lock);
	apm_infop1->apm_private = NULL;
	mutex_exit(&apm_infop1->apm_lock);
	mutex_enter(&apm_infop2->apm_lock);
	apm_infop2->apm_private = NULL;
	mutex_exit(&apm_infop2->apm_lock);

	if (audio_sup_unregister_apm(statep, AUDIO) == AUDIO_FAILURE) {
		ATRACE("am_detach() audio_sup_unregister_apm() "
			"AUDIO failed", statep);
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
		    "detach() audio_sup_unregister_apm() "
		    "AUDIO failed");
	}

	if (audio_sup_unregister_apm(statep, AUDIOCTL) == AUDIO_FAILURE) {
		ATRACE("am_detach() audio_sup_unregister_apm() "
			"AUDIOCTL failed", statep);
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
		    "detach() audio_sup_unregister_apm() "
		    "AUDIOCTL failed");
	}

	ATRACE("am_detach() done", statep);

	return (AUDIO_SUCCESS);

fail:
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*stpptr));
	return (AUDIO_FAILURE);

}	/* am_detach() */

/*
 * am_get_audio()
 *
 * Description:
 *	This routine directs the call to get audio depending on whether or
 *	not the Codec is a traditional or multi-channel Codec. It also does
 *	some error checking to make sure the call is valid.
 *
 *	It is an error for the number of samples to not be modulo the
 *	hardware's number of channels. The old diaudio driver would hang
 *	the channel until it was closed. We throw away enough of the damaged
 *	sample and press on.
 *
 *	We support devices that accept only unsigned linear PCM by translating
 *	the final data, if required.
 *
 *	NOTE: The variable "samples" is the number of samples the hardware
 *		wants. So it is samples at the hardware's sample rate.
 *
 * Arguments:
 *	audiohdl_t	handle	Handle to the device
 *	void		*buf	The buffer to place the audio into
 *	int		channel	For multi-channel Codecs this is the channel
 *				that will be playing the sound.
 *	int		samples	The number of samples to get
 *
 * Returns
 *	>= 0			The number of samples transferred to the buffer
 *	AUDIO_FAILURE		An error has occurred
 */
int
am_get_audio(audiohdl_t handle, void *buf, int channel, int samples)
{
	audio_state_t		*statep = AUDIO_HDL2STATE(handle);
	audio_apm_info_t	*apm_infop;
	am_apm_private_t	*stpptr;
	am_ad_info_t		*ad_infop;
	uint_t			hw_channels;
	int			mode;
	int			rc;

	ATRACE_32("in am_get_audio() samples requested", samples);
	ASSERT(statep);

	if ((apm_infop = audio_sup_get_apm_info(statep, AUDIO)) == NULL) {
		ATRACE("am_get_audio() audio_sup_get_apm_info() AUDIO failed",
		    statep);
		audio_sup_log(AUDIO_STATE2HDL(statep),
		    CE_NOTE, "get_audio() "
		    "audio_sup_get_apm_info() AUDIO failed, audio lost");
		return (AUDIO_FAILURE);
	}

	ad_infop = apm_infop->apm_ad_infop;
	stpptr = apm_infop->apm_private;

	/*
	 * Make sure we don't ask for more data than the mixer can provide.
	 * The mixer uses mixer_bufsize to allocate buffers so we must insure
	 * that we don't try to mix too much and thus get into trouble.
	 */
	if ((samples << AM_INT32_SHIFT) > mixer_bufsize) {
		samples = mixer_bufsize >> AM_INT32_SHIFT;
		ATRACE("am_get_audio() asking for too many samples, resetting",
		    samples);
	}

	/* deal with multi-channel Codecs or regular Codecs */
	if (ad_infop->ad_codec_type == AM_MS_CODEC) {
		ATRACE("am_get_audio() calling am_get_audio_multi()", statep);
		ASSERT(channel != AUDIO_NO_CHANNEL);
		rc = am_get_audio_multi(statep, buf, channel, samples);
		ATRACE_32("am_get_audio() am_get_audio_multi() returning", rc);
	} else {
		ASSERT(ad_infop->ad_codec_type == AM_TRAD_CODEC);
		ASSERT(channel == AUDIO_NO_CHANNEL);

		/* make sure the # of samples is modulo the # of H/W channels */
		hw_channels = stpptr->am_hw_pchs;
		if (hw_channels != AUDIO_CHANNELS_MONO &&
		    (samples % hw_channels) != 0) {
			ATRACE_32("am_get_audio() bad sample size", samples);
			samples -= samples % hw_channels;
		}

		mode = stpptr->am_pstate->apm_mode;
		if (mode == AM_MIXER_MODE) {
			ATRACE("am_get_audio() "
			    "calling am_get_audio_trad_mixer()", statep);
			rc = am_get_audio_trad_mixer(statep, apm_infop, buf,
			    samples);
			ATRACE_32("am_get_audio() "
			    "am_get_audio_trad_mixer() returning", rc);
		} else {
			ASSERT(mode == AM_COMPAT_MODE);
			ATRACE("am_get_audio() "
			    "calling am_get_audio_trad_compat()", statep);
			rc = am_get_audio_trad_compat(statep, apm_infop, buf,
			    samples);
			ATRACE_32("am_get_audio() "
			    "am_get_audio_trad_compat() returning", rc);
		}
	}

	return (rc);

}	/* am_get_audio() */

/*
 * am_hw_state_change()
 *
 * Description:
 *	This routine provides feedback from the audio driver to the mixer
 *	when a user has caused a state change. Usually this is by a button
 *	or knob that the user presses or turns on a speaker or mic. Currently
 *	support for this feedback is somewhat limited as we only support
 *	gain, balance, and mute.
 *
 *	NOTE: We don't include a channel argument because user input is
 *		fairly limited, it is oriented towards the master hardware
 *		device.
 *
 *	NOTE: Unlike the ioctl()s, we don't increment acp_tq_cnt. acp_tq_cnt
 *		is on a per channel basis and we aren't doing this work for any
 *		one channel, but for the whole device. This means that there
 *		aren't any close()s that are going to wait for these tasks to
 *		complete.
 *
 *	NOTE: Mute is a toggle from the current setting.
 *
 * Arguments:
 *	audiohdl_t	handle		Handle to the device
 *	int		cmd		Command for update
 *	int		dir		AUDIO_PLAY or AUDIO_RECORD
 *	int		value		The value to scale
 *	int		sleep		AUDIO_NO_SLEEP or AUDIO_SLEEP
 *
 * Returns:
 *	AUDIO_SUCCESS			Command queued up on the taskq
 *	AUDIO_FAILURE			Bad argument, can't allocate memory, etc
 */
int
am_hw_state_change(audiohdl_t handle, int cmd, int dir, int value, int sleep)
{
	audio_state_t		*statep = AUDIO_HDL2STATE(handle);
	audio_apm_info_t	*apm_infop;
	am_ad_info_t		*ad_infop;
	am_apm_private_t	*stpptr;
	am_state_ch_args_t	*arg;

	ATRACE("in am_hw_state_change()", handle);

	/* make sure the handle is good */
	if (handle == NULL) {
		ATRACE("am_hw_state_change() bad handle", handle);
		return (AUDIO_FAILURE);
	}

	/* don't allow both play and record */
	if ((dir & AUDIO_BOTH) == AUDIO_BOTH) {
		ATRACE_32("am_hw_state_change() bad direction", dir);
		return (AUDIO_FAILURE);
	}

	/* don't allow both sleep and no sleep */
	if (sleep == (AUDIO_NO_SLEEP|AUDIO_SLEEP)) {
		ATRACE_32("am_hw_state_change() bad sleep", sleep);
		return (AUDIO_FAILURE);
	}
	if (sleep == AUDIO_SLEEP) {
		sleep = KM_SLEEP;
	} else {
		ASSERT(sleep == AUDIO_NO_SLEEP);
		sleep = KM_NOSLEEP;
	}

	if ((apm_infop = audio_sup_get_apm_info(statep, AUDIO)) == NULL) {
		ATRACE("am_hw_state_change() "
		    "audio_sup_get_apm_info() AUDIO failed", statep);
		audio_sup_log(AUDIO_STATE2HDL(statep),
		    CE_NOTE, "am_hw_state_change() "
		    "audio_sup_get_apm_info() AUDIO failed");
		return (AUDIO_FAILURE);
	}
	stpptr = apm_infop->apm_private;

	/* Check if we have a valid taskq */
	if (stpptr->am_taskq == NULL) {
		ATRACE("am_hw_state_change() taskq not setup", stpptr);
		return (AUDIO_FAILURE);
	}

	switch (cmd) {
	case AM_HWSC_SET_GAIN_ABS:
		/*FALLTHROUGH*/
	case AM_HWSC_SET_BAL_ABS:
		/*FALLTHROUGH*/
	case AM_HWSC_SET_GAIN_DELTA:
		/*FALLTHROUGH*/
	case AM_HWSC_SET_BAL_DELTA:
		/*FALLTHROUGH*/
	case AM_HWSC_MUTE_TOGGLE:
		/* does the h/w support the direction? */
		ad_infop = apm_infop->apm_ad_infop;
		if ((dir == AUDIO_PLAY &&
		    !(ad_infop->ad_defaults->hw_features &
		    AUDIO_HWFEATURE_PLAY)) ||
		    (dir == AUDIO_RECORD &&
		    !(ad_infop->ad_defaults->hw_features &
		    AUDIO_HWFEATURE_RECORD))) {
			ATRACE_32("am_hw_state_change() dir !supported", dir);
			return (AUDIO_FAILURE);
		}

		/* allocate argument memory for taskq */
		if ((arg = kmem_alloc(sizeof (*arg), sleep)) == NULL) {
			ATRACE("am_hw_state_change() alloc failed", statep);
			return (AUDIO_FAILURE);
		}
		arg->asca_statep = statep;
		arg->asca_apm_infop = apm_infop;
		arg->asca_cmd = cmd;
		arg->asca_dir = dir;
		arg->asca_value = value;

		break;
	case AM_HWSC_ONLINE:
		mutex_enter(&apm_infop->apm_lock);
		stpptr->am_flags |= AM_PRIV_ON_LINE;
		mutex_exit(&apm_infop->apm_lock);

		return (AUDIO_SUCCESS);
	case AM_HWSC_OFFLINE:
		mutex_enter(&apm_infop->apm_lock);
		stpptr->am_flags &= ~AM_PRIV_ON_LINE;
		mutex_exit(&apm_infop->apm_lock);

		return (AUDIO_SUCCESS);
	default:
		ATRACE_32("am_hw_state_change() bad command", cmd);
		return (AUDIO_FAILURE);
	}

	/* schedule the task */
	if (audio_sup_taskq_dispatch(stpptr->am_taskq, am_hw_task,
	    arg, sleep) == AUDIO_FAILURE) {
		kmem_free(arg, sizeof (*arg));
		ATRACE("am_hw_state_change() taskq sched failed", statep);
		return (AUDIO_FAILURE);
	}

	ATRACE("am_hw_state_change() done", handle);

	return (AUDIO_SUCCESS);

}	/* am_hw_state_change() */

/*
 * am_play_shutdown()
 *
 * Description:
 *	This routine is used to clean things up when the Audio Driver will
 *	no longer be servicing it's play interrupts. I.e., play interrupts
 *	have been turned off.
 *
 *	This routine makes sure that any DRAINs waiting for an interrupt are
 *	cleared.
 *
 *	It is also used to coordinate shutting down play so that we can
 *	switch between MIXER and COMPAT modes.
 *
 * Arguments:
 *	audiohdl_t	handle		Handle to the device
 *	int		channel		For multi-stream Codecs this is the
 *					stream to shutdown.
 *
 * Returns:
 *	void
 */
void
am_play_shutdown(audiohdl_t handle, int channel)
{
	audio_state_t			*statep = AUDIO_HDL2STATE(handle);
	audio_apm_info_t		*apm_infop;
	am_ad_info_t			*ad_infop;

	ATRACE("in am_play_shutdown()", handle);
	ASSERT(statep);

	if ((apm_infop = audio_sup_get_apm_info(statep, AUDIO)) == NULL) {
		ATRACE("am_play_shutdown() audio_sup_get_apm_info() failed", 0);
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
		    "play_shutdown() audio_sup_get_apm_info() failed");
		return;
	}
	ad_infop = apm_infop->apm_ad_infop;

	/* deal with multi-channel Codecs vs. regular Codecs */
	if (ad_infop->ad_codec_type == AM_MS_CODEC) {
		ATRACE("am_play_shutdown() calling shutdown_multi()", ad_infop);
		am_play_shutdown_multi(handle, channel);
		ATRACE("am_play_shutdown() shutdown_multi() done", ad_infop);
	} else {
		ASSERT(ad_infop->ad_codec_type == AM_TRAD_CODEC);
		ATRACE("am_play_shutdown() calling shutdown_trad()", ad_infop);
		am_play_shutdown_trad(handle, apm_infop);
		ATRACE("am_play_shutdown() shutdown_trad() done", ad_infop);
	}

	ATRACE("am_play_shutdown() returning", statep);

	return;

}	/* am_play_shutdown() */

/*
 * am_send_audio()
 *	This routine directs the call to send audio depending on whether or
 *	not the Codec is a traditional or multi-channel Codec. It also does
 *	some error checking to make sure the call is valid.
 *
 *	It is an error for the number of samples to not be modulo the
 *	hardware's number of channels. The old diaudio driver would hang
 *	the channel until it was closed. We throw away enough of the damaged
 *	sample and press on.
 *
 *	We support devices that provide only unsigned linear PCM by translating
 *	the data to signed before it is used.
 *
 *	NOTE: The variable "samples" is the number of samples the hardware
 *		sends. So it is samples at the hardware's sample rate.
 *
 * Description:
 *
 * Arguments:
 *	audiohdl_t	handle		Handle to the device
 *	void		*buf		The buffer the audio is in
 *	int		channel		For multi-channel Codecs this is the
 *					channel that will be receiving the audio
 *	int		samples		The number of samples to send
 *
 * Returns
 *	void
 */
void
am_send_audio(audiohdl_t handle, void *buf, int channel, int samples)
{
	audio_state_t			*statep = AUDIO_HDL2STATE(handle);
	audio_apm_info_t		*apm_infop;
	am_apm_private_t		*stpptr;
	am_ad_info_t			*ad_infop;
	size_t				size;
	uint_t				hw_channels;
	int				mode;

	ATRACE("in am_send_audio()", handle);
	ATRACE("am_send_audio() buf", buf);
	ATRACE("am_send_audio() channel", channel);
	ATRACE("am_send_audio() samples", samples);
	ASSERT(statep);

	/* reject processing 0 or less samples */
	if (samples <= 0 || samples > AM_MAX_SAMPLES) {
		ATRACE_32("am_send_audio() bad samples arg #1, returning",
		    samples);
		return;
	}

	if ((apm_infop = audio_sup_get_apm_info(statep, AUDIO)) == NULL) {
		ATRACE("am_send_audio() audio_sup_get_apm_info() AUDIO failed",
		    statep);
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
		    "send_audio() audio_sup_get_apm_info() "
		    "AUDIO failed, recorded audio lost");
		return;
	}

	ad_infop = apm_infop->apm_ad_infop;

	/* deal with multi-channel Codecs or regular Codecs */
	if (ad_infop->ad_codec_type == AM_MS_CODEC) {
		ATRACE("am_send_audio() calling am_send_audio_multi()", statep);
		ASSERT(channel != AUDIO_NO_CHANNEL);
		am_send_audio_multi(statep, apm_infop->apm_ad_infop, buf,
		    channel, samples);
		ATRACE_32("am_send_audio() am_send_audio_multi() returning", 0);
	} else {
		ASSERT(ad_infop->ad_codec_type == AM_TRAD_CODEC);
		ASSERT(channel == AUDIO_NO_CHANNEL);

		/* make sure the # of samples is modulo the # of H/W channels */
		stpptr = apm_infop->apm_private;
		hw_channels = stpptr->am_hw_rchs;
		if (hw_channels != AUDIO_CHANNELS_MONO &&
		    (samples % hw_channels) != 0) {
			ATRACE_32("am_send_audio() bad sample size", samples);
			samples -= samples % hw_channels;
			ATRACE("am_send_audio() adjusted samples", samples);
			if (samples <= 0) {
				ATRACE_32("am_send_audio() bad samples arg #2",
				    samples);
				return;
			}
		}

		/* make sure the send buffer is large enough */
		size = ((size_t)samples) << AM_TIMES_4_SHIFT;
		ATRACE("am_send_audio() size", size);

		mutex_enter(&apm_infop->apm_lock);

		if (stpptr->am_send_size < size) {
			ATRACE("am_send_audio() old am_send_buf",
			    stpptr->am_send_buf);
			ATRACE("am_send_audio() old am_send_size",
			    stpptr->am_send_size);
			if (stpptr->am_send_size) {
				kmem_free(stpptr->am_send_buf,
				    stpptr->am_send_size);
			}
			stpptr->am_send_buf = kmem_alloc(size, KM_NOSLEEP);
			if (stpptr->am_send_buf == NULL) {
				stpptr->am_send_size = 0;
				mutex_exit(&apm_infop->apm_lock);
				audio_sup_log(AUDIO_STATE2HDL(statep),
				    CE_NOTE, "!mixer: send_audio_trad() "
				    "couldn't allocate send buffer, audio "
				    "lost");
				return;
			}
			stpptr->am_send_size = size;
			ATRACE("am_send_audio() new am_send_buf",
			    stpptr->am_send_buf);
			ATRACE("am_send_audio() new am_send_size",
			    stpptr->am_send_size);
		}
		mutex_exit(&apm_infop->apm_lock);

		/* convert to canonical format */
		am_convert_to_int(buf, stpptr->am_send_buf, samples,
		    stpptr->am_hw_rprec, stpptr->am_hw_renc, stpptr->am_rflags);

		mode = stpptr->am_pstate->apm_mode;
		if (mode == AM_MIXER_MODE) {
			ATRACE("am_send_audio() "
			    "calling am_send_audio_trad_mixer()", statep);
			am_send_audio_trad_mixer(statep, apm_infop,
			    stpptr->am_send_buf, samples);
			ATRACE_32("am_send_audio() "
			    "am_send_audio_trad_mixer() returning", 0);
		} else {
			ASSERT(mode == AM_COMPAT_MODE);
			ATRACE("am_send_audio() "
			    "calling am_send_audio_trad_compat()", statep);
			am_send_audio_trad_compat(statep, apm_infop,
			    stpptr->am_send_buf, samples);
			ATRACE_32("am_send_audio() "
			    "am_send_audio_trad_compat() returning", 0);
		}
	}

}	/* am_send_audio() */

/*
 * am_get_src_data()
 *
 * Description:
 *	This routine returns the PLAY or RECORD sample rate conversion
 *	data structure that is saved in the channel's private data structure.
 *
 * Arguments:
 *	srchdl_t	handle		SRC handle
 *	int		dir		AUDIO_PLAY or AUDIO_RECORD
 *
 * Returns:
 *	void *				Pointer to the sample rate conversion
 *					structure
 */
void *
am_get_src_data(srchdl_t handle, int dir)
{
	audio_ch_t		*chptr = AM_SRC_HDL2CHPTR(handle);
	am_ch_private_t		*chpptr = chptr->ch_private;
	void			*data;

	ATRACE("in am_get_src_data()", chptr);
	ATRACE("am_get_src_data() chpptr", chpptr);
	ATRACE_32("am_get_src_data() dir", dir);

	if (dir == AUDIO_PLAY) {
		ATRACE("am_get_src_data() PLAY returning",
		    chpptr->acp_play_src_data);
		data = chpptr->acp_play_src_data;
	} else {
		ASSERT(dir == AUDIO_RECORD);
		ATRACE("am_get_src_data() CAPTURE returning",
		    chpptr->acp_rec_src_data);
		data = chpptr->acp_rec_src_data;
	}

	return (data);

}	/* am_get_src_data() */

/*
 * am_set_src_data()
 *
 * Description:
 *	This routine sets the PLAY or RECORD sample rate conversion
 *	data structure pointer with the pointer passed in.
 *
 * Arguments:
 *	srchdl_t	handle		SRC handle
 *	int		dir		AUDIO_PLAY or AUDIO_RECORD
 *	void		*data		The sample rate conversion data
 *
 * Returns:
 *	void
 */
void
am_set_src_data(srchdl_t handle, int dir, void *data)
{
	audio_ch_t		*chptr = AM_SRC_HDL2CHPTR(handle);
	am_ch_private_t		*chpptr = chptr->ch_private;

	ATRACE("in am_set_src_data()", chptr);
	ATRACE_32("am_set_src_data() dir", dir);
	ATRACE("am_set_src_data() data", data);

	if (dir == AUDIO_PLAY) {
		ATRACE("am_set_src_data() setting PLAY", data);
		chpptr->acp_play_src_data = data;
	} else {
		ASSERT(dir == AUDIO_RECORD);
		ATRACE("am_set_src_data() setting CAPTURE", data);
		chpptr->acp_rec_src_data = data;
	}

}	/* am_set_src_data() */

/*
 * Private utilities used by this and other audio mixer files.
 */

/*
 * am_ad_pause_play()
 *
 * Description:
 *	The official way to call into the audio driver. This uses a CV
 *	to ensure that only one call into the audio driver can be made
 *	at any one time. Thus the audio driver doesn't have to worry about
 *	serialization of the entry points.
 *
 *	We further restrict this call such that if there aren't any open
 *	play channels we don't allow this call to succeed. This implies that
 *	there has been at least one call to ad_setup() before play is started
 *	and there is still an ad_teardown() call to come. This situation is
 *	possible if only AUDIOCTL and no AUDIO channels are open and one of
 *	the AUDIOCTL channels does an AUDIO_SETINFO to unpause.
 *
 * Arguments:
 *	audio_state_t	*statep		Ptr to the dev instance's state
 *	am_apm_private_t *stpptr	Ptr to APM private data
 *	am_ad_info_t	*ad_infop	Ptr to the Audio Driver's config info
 *	int		stream		Which stream to pause
 *
 * Returns:
 *	void
 */
void
am_ad_pause_play(audio_state_t *statep, am_apm_private_t *stpptr,
	am_ad_info_t *ad_infop, int stream)
{
	ATRACE("in am_ad_pause_play()", statep);
	ATRACE_32("am_ad_pause_play() stream", stream);
	ASSERT(statep);

	/* make sure we can play */
	mutex_enter(&statep->as_lock);
	if (stpptr->am_out_chs == 0) {
		ATRACE_32("am_ad_pause_play() no playing channels",
		    stpptr->am_out_chs);
		mutex_exit(&statep->as_lock);
		return;
	}
	ATRACE_32("am_ad_pause_play() playing channels", stpptr->am_out_chs);
	mutex_exit(&statep->as_lock);

	/* wait for all other calls into the audio driver to return */
	am_serialize_ad_access(stpptr);

	ATRACE("am_ad_pause_play() calling ad_pause_play()", ad_infop);
	ad_infop->ad_entry->ad_pause_play(AUDIO_STATE2HDL(statep), stream);
	ATRACE("am_ad_pause_play() ad_pause_play() done", ad_infop);

	/* we're done, so release any waiting threads */
	am_release_ad_access(stpptr);

	ATRACE("am_ad_pause_play() returning", 0);

}	/* am_ad_pause_play() */

/*
 * am_ad_set_config()
 *
 * Description:
 *	The official way to call into the audio driver. This uses a CV
 *	to ensure that only one call into the audio driver can be made
 *	at any one time. Thus the audio driver doesn't have to worry about
 *	serialization of the entry points.
 *
 * Arguments:
 *	audio_state_t	*statep		Ptr to the dev instance's state
 *	am_apm_private_t *stpptr	Ptr to APM private data
 *	am_ad_info_t	*ad_infop	Ptr to the Audio Driver's config info
 *	int		stream		Which stream to set config
 *	int		command		The configuration command
 *	int		dir		AUDIO_PLAY or AUDIO_RECORD
 *	int		arg1		Command argument #1
 *	int		arg2		Command argument #2
 *	int		serialize	Serialize access to the audio driver
 *
 * Returns:
 *	AUDIO_SUCCESS			Configuration set
 *	AUDIO_FAILURE			Configuration not set
 */
int
am_ad_set_config(audio_state_t *statep, am_apm_private_t *stpptr,
	am_ad_info_t *ad_infop, int stream, int command, int dir, int arg1,
	int arg2, int serialize)
{
	int		rc;

	ATRACE("in am_ad_set_config()", statep);
	ATRACE_32("am_ad_set_config() stream", stream);
	ASSERT(statep);

	/* wait for all other calls into the audio driver to return */
	if (serialize) {
		am_serialize_ad_access(stpptr);
	}

	ATRACE("am_ad_set_config() calling ad_set_config()", ad_infop);
	rc = ad_infop->ad_entry->ad_set_config(AUDIO_STATE2HDL(statep), stream,
	    command, dir, arg1, arg2);
	ATRACE_32("am_ad_set_config() ad_set_config() done", rc);

	/* we're done, so release any waiting threads */
	if (serialize) {
		am_release_ad_access(stpptr);
	}

	ATRACE_32("am_ad_set_config() returning", rc);

	return (rc);

}	/* am_ad_set_config() */

/*
 * am_ad_set_format()
 *
 * Description:
 *	The official way to call into the audio driver. This uses a CV
 *	to ensure that only one call into the audio driver can be made
 *	at any one time. Thus the audio driver doesn't have to worry about
 *	serialization of the entry points.
 *
 *	Furthermore, if the device was active we call the proper start
 *	routine. This kicks things off if the driver had to stop things
 *	to change the format, but has a hard time restarting afterwards.
 *
 * Arguments:
 *	audio_state_t	*statep		Ptr to the dev instance's state
 *	am_apm_private_t *stpptr	Ptr to APM private data
 *	am_ad_info_t	*ad_infop	Ptr to the Audio Driver's config info
 *	int		stream		Which stream to set format
 *	int		dir		AUDIO_PLAY or AUDIO_RECORD
 *	int		sample_rate	Sample rate to set
 *	int		channels	Number of channels to set
 *	int		precision	Precision to set
 *	int		encoding	Encoding to set
 *	int		serialize	Serialize access to audio driver
 *
 * Returns:
 *	AUDIO_SUCCESS			Format set
 *	AUDIO_FAILURE			Format not set
 */
int
am_ad_set_format(audio_state_t *statep, am_apm_private_t *stpptr,
	am_ad_info_t *ad_infop, int stream, int dir, int sample_rate,
	int channels, int precision, int encoding, int serialize)
{
	audio_info_t	*hw_info = &stpptr->am_hw_info;
	int		rc;

	ATRACE("in am_ad_set_format()", statep);
	ATRACE_32("am_ad_set_format() stream", stream);
	ASSERT(statep);

	/* wait for all other calls into the audio driver to return */
	if (serialize) {
		am_serialize_ad_access(stpptr);
	}

	ATRACE("am_ad_set_format() calling ad_set_format()", ad_infop);
	rc = ad_infop->ad_entry->ad_set_format(AUDIO_STATE2HDL(statep), stream,
	    dir, sample_rate, channels, precision, encoding);
	ATRACE_32("am_ad_set_format() ad_set_format() done", rc);

	if (dir == AUDIO_PLAY) {
		mutex_enter(&statep->as_lock);
		if (stpptr->am_out_chs != 0 && hw_info->play.active) {
			mutex_exit(&statep->as_lock);
			ATRACE("am_ad_set_format() restart play", hw_info);
			(void) ad_infop->ad_entry->ad_start_play(
			    AUDIO_STATE2HDL(statep), stream);
			ATRACE("am_ad_set_format() restart play done", 0);
		} else {
			mutex_exit(&statep->as_lock);
		}
	} else {
		ASSERT(dir == AUDIO_RECORD);
		mutex_enter(&statep->as_lock);
		if (stpptr->am_in_chs != 0 && hw_info->record.active) {
			mutex_exit(&statep->as_lock);
			ATRACE("am_ad_set_format() restart record", hw_info);
			(void) ad_infop->ad_entry->ad_start_record(
			    AUDIO_STATE2HDL(statep), stream);
			ATRACE("am_ad_set_format() restart record done", 0);
		} else {
			mutex_exit(&statep->as_lock);
		}
	}

	/* we're done, so release any waiting threads */
	if (serialize) {
		am_release_ad_access(stpptr);
	}

	ATRACE("am_ad_set_format() returning", rc);

	return (rc);

}	/* am_ad_set_format() */

/*
 * am_ad_setup()
 *
 * Description:
 *	The official way to call into the audio driver. This uses a CV
 *	to ensure that only one call into the audio driver can be made
 *	at any one time. Thus the audio driver doesn't have to worry about
 *	serialization of the entry points.
 *
 * Arguments:
 *	audio_state_t	*statep		Ptr to the dev instance's state
 *	am_apm_private_t *stpptr	Ptr to APM private data
 *	am_ad_info_t	*ad_infop	Ptr to the Audio Driver's config info
 *	int		stream		Which stream to set format
 *	int		flags		Setup flags
 *
 * Returns:
 *	AUDIO_SUCCESS			Setup successful
 *	AUDIO_FAILURE			Setup failed
 */
int
am_ad_setup(audio_state_t *statep, am_apm_private_t *stpptr,
	am_ad_info_t *ad_infop, int stream, int flags)
{
	int		rc;

	ATRACE("in am_ad_setup()", statep);
	ATRACE_32("am_ad_setup() stream", stream);
	ASSERT(statep);

	/* if there isn't an ad_setup() routine then we just return success */
	if (ad_infop->ad_entry->ad_setup == NULL) {
		ATRACE("am_ad_setup() not defined, returning", statep);
		return (AUDIO_SUCCESS);
	}

	/* wait for all other calls into the audio driver to return */
	am_serialize_ad_access(stpptr);

	ATRACE("am_ad_setup() calling ad_setup()", ad_infop);
	rc = ad_infop->ad_entry->ad_setup(AUDIO_STATE2HDL(statep), stream,
	    flags);
	ATRACE_32("am_ad_setup() ad_setup() done", rc);

	/* we're done, so release any waiting threads */
	am_release_ad_access(stpptr);

	ATRACE("am_ad_setup() returning", rc);

	return (rc);

}	/* am_ad_setup() */

/*
 * am_ad_start_play()
 *
 * Description:
 *	The official way to call into the audio driver. This uses a CV
 *	to ensure that only one call into the audio driver can be made
 *	at any one time. Thus the audio driver doesn't have to worry about
 *	serialization of the entry points.
 *
 *	We further restrict this call such that if there aren't any open
 *	play channels we don't allow this call to succeed. This implies that
 *	there has been at least one call to ad_setup() before play is started
 *	and there is still an ad_teardown() call to come. This situation is
 *	possible if only AUDIOCTL and no AUDIO channels are open and one of
 *	the AUDIOCTL channels does an AUDIO_SETINFO to unpause.
 *
 * Arguments:
 *	audio_state_t	*statep		Ptr to the dev instance's state
 *	am_apm_private_t *stpptr	Ptr to APM private data
 *	am_ad_info_t	*ad_infop	Ptr to the Audio Driver's config info
 *	int		stream		Which stream to start play
 *	int		serialize	Serialize access to the audio driver
 *
 * Returns:
 *	AUDIO_SUCCESS			Start play successful
 *	AUDIO_FAILURE			Start play not successful
 */
int
am_ad_start_play(audio_state_t *statep, am_apm_private_t *stpptr,
	am_ad_info_t *ad_infop, int stream, int serialize)
{
	int		rc;

	ATRACE("in am_ad_start_play()", statep);
	ATRACE_32("am_ad_start_play() stream", stream);
	ASSERT(statep);

	/* make sure we can play */
	mutex_enter(&statep->as_lock);
	if (stpptr->am_out_chs == 0) {
		ATRACE_32("am_ad_start_play() no playing channels",
		    stpptr->am_out_chs);
		mutex_exit(&statep->as_lock);
		return (AUDIO_FAILURE);
	}
	ATRACE_32("am_ad_start_play() playing channels", stpptr->am_out_chs);
	mutex_exit(&statep->as_lock);

	/* wait for all other calls into the audio driver to return */
	if (serialize) {
		am_serialize_ad_access(stpptr);
	}

	ATRACE("am_ad_start_play() calling ad_start_play()", ad_infop);
	rc = ad_infop->ad_entry->ad_start_play(AUDIO_STATE2HDL(statep), stream);
	ATRACE_32("am_ad_start_play() ad_start_play() done", rc);

	/* we're done, so release any waiting threads */
	if (serialize) {
		am_release_ad_access(stpptr);
	}

	ATRACE("am_ad_start_play() returning", rc);

	return (rc);

}	/* am_ad_start_play() */

/*
 * am_ad_start_record()
 *
 * Description:
 *	The official way to call into the audio driver. This uses a CV
 *	to ensure that only one call into the audio driver can be made
 *	at any one time. Thus the audio driver doesn't have to worry about
 *	serialization of the entry points.
 *
 *	We further restrict this call such that if there aren't any open
 *	record channels we don't allow this call to succeed. This implies that
 *	there has been at least one call to ad_setup() before record is started
 *	and there is still an ad_teardown() call to come. This situation is
 *	possible if only AUDIOCTL and no AUDIO channels are open and one of
 *	the AUDIOCTL channels does an AUDIO_SETINFO to unpause.
 *
 * Arguments:
 *	audio_state_t	*statep		Ptr to the dev instance's state
 *	am_apm_private_t *stpptr	Ptr to APM private data
 *	am_ad_info_t	*ad_infop	Ptr to the Audio Driver's config info
 *	int		stream		Which stream to start record
 *	int		serialize	Serialize access to the audio driver
 *
 * Returns:
 *	AUDIO_SUCCESS			Start record successful
 *	AUDIO_FAILURE			Start record not successful
 */
int
am_ad_start_record(audio_state_t *statep, am_apm_private_t *stpptr,
	am_ad_info_t *ad_infop, int stream, int serialize)
{
	int		rc;

	ATRACE("in am_ad_start_record()", statep);
	ATRACE_32("am_ad_start_record() stream", stream);
	ASSERT(statep);

	/* make sure we can record */
	mutex_enter(&statep->as_lock);
	if (stpptr->am_in_chs == 0) {
		ATRACE_32("am_ad_start_record() no record channels",
		    stpptr->am_in_chs);
		mutex_exit(&statep->as_lock);
		return (AUDIO_FAILURE);
	}
	ATRACE_32("am_ad_start_record() record channels", stpptr->am_in_chs);
	mutex_exit(&statep->as_lock);

	/* wait for all other calls into the audio driver to return */
	if (serialize) {
		am_serialize_ad_access(stpptr);
	}

	ATRACE("am_ad_start_record() calling ad_start_record()", ad_infop);
	rc = ad_infop->ad_entry->ad_start_record(AUDIO_STATE2HDL(statep),
	    stream);
	ATRACE_32("am_ad_start_record() ad_start_record() done", rc);

	/* we're done, so release any waiting threads */
	if (serialize) {
		am_release_ad_access(stpptr);
	}

	ATRACE("am_ad_start_record() returning", rc);

	return (rc);

}	/* am_ad_start_record() */

/*
 * am_ad_stop_play()
 *
 * Description:
 *	The official way to call into the audio driver. This uses a CV
 *	to ensure that only one call into the audio driver can be made
 *	at any one time. Thus the audio driver doesn't have to worry about
 *	serialization of the entry points.
 *
 *	We further restrict this call such that if there aren't any open
 *	play channels we don't allow this call to succeed. This implies that
 *	there has been at least one call to ad_setup() before play is started
 *	and there is still an ad_teardown() call to come. This situation is
 *	possible if only AUDIOCTL and no AUDIO channels are open and one of
 *	the AUDIOCTL channels does an AUDIO_SETINFO to unpause.
 *
 * Arguments:
 *	audio_state_t	*statep		Ptr to the dev instance's state
 *	am_apm_private_t *stpptr	Ptr to APM private data
 *	am_ad_info_t	*ad_infop	Ptr to the Audio Driver's config info
 *	int		stream		Which stream to stop playing
 *
 * Returns:
 *	void
 */
void
am_ad_stop_play(audio_state_t *statep, am_apm_private_t *stpptr,
	am_ad_info_t *ad_infop, int stream)
{
	ATRACE("in am_ad_stop_play()", statep);
	ATRACE_32("am_ad_stop_play() stream", stream);
	ASSERT(statep);

	/* make sure we can play */
	mutex_enter(&statep->as_lock);
	if (stpptr->am_out_chs == 0) {
		ATRACE_32("am_ad_stop_play() no playing channels",
		    stpptr->am_out_chs);
		mutex_exit(&statep->as_lock);
		return;
	}
	ATRACE_32("am_ad_stop_play() playing channels", stpptr->am_out_chs);
	mutex_exit(&statep->as_lock);

	/* wait for all other calls into the audio driver to return */
	am_serialize_ad_access(stpptr);

	ATRACE("am_ad_stop_play() calling ad_stop_play()", ad_infop);
	ad_infop->ad_entry->ad_stop_play(AUDIO_STATE2HDL(statep), stream);
	ATRACE_32("am_ad_stop_play() ad_stop_play() done", stream);

	/* we're done, so release any waiting threads */
	am_release_ad_access(stpptr);

	ATRACE("am_ad_stop_play() returning", stream);

}	/* am_ad_stop_play() */

/*
 * am_ad_stop_record()
 *
 * Description:
 *	The official way to call into the audio driver. This uses a CV
 *	to ensure that only one call into the audio driver can be made
 *	at any one time. Thus the audio driver doesn't have to worry about
 *	serialization of the entry points.
 *
 *	We further restrict this call such that if there aren't any open
 *	record channels we don't allow this call to succeed. This implies that
 *	there has been at least one call to ad_setup() before record is started
 *	and there is still an ad_teardown() call to come. This situation is
 *	possible if only AUDIOCTL and no AUDIO channels are open and one of
 *	the AUDIOCTL channels does an AUDIO_SETINFO to unpause.
 *
 * Arguments:
 *	audio_state_t	*statep		Ptr to the dev instance's state
 *	am_apm_private_t *stpptr	Ptr to APM private data
 *	am_ad_info_t	*ad_infop	Ptr to the Audio Driver's config info
 *	int		stream		Which stream to stop recording
 *
 * Returns:
 *	void
 */
void
am_ad_stop_record(audio_state_t *statep, am_apm_private_t *stpptr,
	am_ad_info_t *ad_infop, int stream)
{
	ATRACE("in am_ad_stop_record()", statep);
	ATRACE_32("am_ad_stop_record() stream", stream);
	ASSERT(statep);

	/* make sure we can record */
	mutex_enter(&statep->as_lock);
	if (stpptr->am_in_chs == 0) {
		ATRACE_32("am_ad_stop_record() no record channels",
		    stpptr->am_in_chs);
		mutex_exit(&statep->as_lock);
		return;
	}
	ATRACE_32("am_ad_stop_record() record channels", stpptr->am_in_chs);
	mutex_exit(&statep->as_lock);

	/* wait for all other calls into the audio driver to return */
	am_serialize_ad_access(stpptr);

	ATRACE("am_ad_stop_record() calling ad_stop_record()", ad_infop);
	ad_infop->ad_entry->ad_stop_record(AUDIO_STATE2HDL(statep), stream);
	ATRACE_32("am_ad_stop_record() ad_stop_record() done", stream);

	/* we're done, so release any waiting threads */
	am_release_ad_access(stpptr);

	ATRACE("am_ad_stop_record() returning", stream);

}	/* am_ad_stop_record() */

/*
 * am_ad_teardown()
 *
 * Description:
 *	The official way to call into the audio driver. This uses a CV
 *	to ensure that only one call into the audio driver can be made
 *	at any one time. Thus the audio driver doesn't have to worry about
 *	serialization of the entry points.
 *
 * Arguments:
 *	audio_state_t	*statep		Ptr to the dev instance's state
 *	am_apm_private_t *stpptr	Ptr to APM private data
 *	am_ad_info_t	*ad_infop	Ptr to the Audio Driver's config info
 *	int		stream		Which stream to set format
 *	int		dir		AUDIO_PLAY and/or AUDIO_RECORD
 *
 * Returns:
 *	void
 */
void
am_ad_teardown(audio_state_t *statep, am_apm_private_t *stpptr,
	am_ad_info_t *ad_infop, int stream, int dir)
{
	ATRACE("in am_ad_teardown()", statep);
	ATRACE_32("am_ad_teardown() stream", stream);
	ASSERT(statep);

	/* if there isn't an ad_teardown() routine then just return success */
	if (ad_infop->ad_entry->ad_teardown == NULL) {
		ATRACE("am_ad_teardown() not defined, returning", statep);
		return;
	}

	/* wait for all other calls into the audio driver to return */
	am_serialize_ad_access(stpptr);

	ATRACE("am_ad_teardown() calling ad_teardown()", ad_infop);
	ad_infop->ad_entry->ad_teardown(AUDIO_STATE2HDL(statep), stream, dir);
	ATRACE_32("am_ad_teardown() ad_teardown() done", stream);

	/* we're done, so release any waiting threads */
	am_release_ad_access(stpptr);

	ATRACE("am_ad_teardown() returning", stream);

}	/* am_ad_teardown() */

/*
 * am_ck_channels()
 *
 * Description:
 *	This routine checks to see if the number of channels passed is one of
 *	the supported number of channels. If hw is set to B_TRUE then we check
 *	against what the hardware can do. If it is set to B_FALSE then we check
 *	against what we know how to translate.
 *
 * Arguments:
 *	am_ad_ch_cap_t	*cptr	Pointer to the play/record capability struct
 *	uint_t		ch	Number of channels to check
 *	boolean_t	hw	If B_TRUE report the true H/W capability
 *
 * Returns:
 *	AUDIO_SCCESS		Valid number of channels
 *	AUDIO_FAILURE		Invalid number of channels
 */
int
am_ck_channels(am_ad_ch_cap_t *cptr, uint_t ch, boolean_t hw)
{
	uint_t		*iptr = cptr->ad_chs;
	int		i;

	ATRACE("in am_ck_channels()", cptr);

	if (hw) {
		/* check against the hardware */
		for (i = 0; *iptr != 0; i++, iptr++) {
			if (*iptr == ch) {
				ATRACE("am_ck_channels() hw true succeeded",
				    iptr);
				return (AUDIO_SUCCESS);
			}
		}
		ATRACE("am_ck_channels() hw true failed", cptr->ad_chs);
		return (AUDIO_FAILURE);
	}

	ASSERT(hw == B_FALSE);

	/* check against all legal number of channels */
	if (ch == AUDIO_CHANNELS_MONO || ch == AUDIO_CHANNELS_STEREO) {
		ATRACE_32("am_ck_channels() hw false succeeded", ch);
		return (AUDIO_SUCCESS);
	}

	ATRACE_32("am_ck_channels() hw false failed", hw);
	return (AUDIO_FAILURE);

}	/* am_ck_channels */

/*
 * am_ck_combinations()
 *
 * Description:
 *	This routine makes sure that the combination of encoding and
 *	precision are legal. If hw is set to B_TRUE then we check against
 *	what the hardware can do. If it is set to B_FALSE then we check
 *	against what we know how to translate. We can translate between all
 *	supported encoding and precision combinations.
 *
 * Arguments:
 *	am_ad_cap_comb_t	*comb	Ptr to the play/rec legal combinations
 *	int			enc	The encoding to check
 *	int			prec	The precision to check
 *	boolean_t		hw	If B_TRUE report the true H/W capability
 *
 * Returns:
 *	AUDIO_SUCCESS		It is a legal combination or value
 *	AUDIO_FAILURE		It is not a legal combination or value
 */
int
am_ck_combinations(am_ad_cap_comb_t *comb, int enc, int prec, boolean_t hw)
{
	am_ad_cap_comb_t	*ptr;

	ATRACE("in am_ck_combinations()", comb);
	ATRACE("am_ck_combinations() enc", enc);
	ATRACE("am_ck_combinations() prec", prec);

	if (hw) {
		/* check against the hardware */
		for (ptr = comb; ptr->ad_prec != 0; ptr++) {
			ATRACE_32("am_ck_combinations() enc", ptr->ad_enc);
			ATRACE_32("am_ck_combinations() prec", ptr->ad_prec);
			if (ptr->ad_prec == prec && ptr->ad_enc == enc) {
				ATRACE("am_ck_combinations() "
				    "found a legal combination", ptr);
				return (AUDIO_SUCCESS);
			}
		}
		ATRACE("am_ck_combinations() not in combination array", 0);
		return (AUDIO_FAILURE);
	}

	ASSERT(hw == B_FALSE);

	/* check against all legal combinations */
	switch (prec) {
	case AUDIO_PRECISION_16:
		/* the only thing it can be is PCM */
		switch (enc) {
		case AUDIO_ENCODING_LINEAR:
			return (AUDIO_SUCCESS);
		default:
			return (AUDIO_FAILURE);
		}
	case AUDIO_PRECISION_8:
		/* we have more choices for 8-bit */
		switch (enc) {
		case AUDIO_ENCODING_LINEAR8:
			/*FALLTHROUGH*/
		case AUDIO_ENCODING_LINEAR:
			/*FALLTHROUGH*/
		case AUDIO_ENCODING_ULAW:
			/*FALLTHROUGH*/
		case AUDIO_ENCODING_ALAW:
			return (AUDIO_SUCCESS);
		default:
			return (AUDIO_FAILURE);
		}
	default:
		ATRACE_32("am_ck_combinations() illegal precision", prec);
		return (AUDIO_FAILURE);
	}

}	/* am_ck_combinations() */

/*
 * am_ck_sample_rate()
 *
 * Description:
 *	The sample rate information list is searched for the sample rate.
 *
 * Arguments:
 *	am_ad_ch_cap_t	*cptr	Pointer to the play/record capability struct
 *	int		mode	AM_MIXER_MODE or AM_COMPAT_MODE
 *	int		sr	Sample rate to check
 *
 * Returns:
 *	AUDIO_SUCCESS		Sample rate found
 *	AUDIO_FAILURE		Invalid sample rate
 */
int
am_ck_sample_rate(am_ad_ch_cap_t *cptr, int mode, int sr)
{
	am_ad_sample_rates_t	*srs;
	uint_t			*ptr;

	ATRACE("in am_ck_sample_rate()", cptr);
	ATRACE_32("am_ck_sample_rate() mode", mode);
	ATRACE_32("am_ck_sample_rate() sample rate", sr);

	if (mode == AM_MIXER_MODE) {
		srs = &cptr->ad_mixer_srs;
	} else {
		srs = &cptr->ad_compat_srs;
	}
	ptr = srs->ad_srs;

	/* check the passed in sample rate against the list */
	if (srs->ad_limits & MIXER_SRS_FLAG_SR_LIMITS) {
		/*
		 * We only check the limits and because we've already done the
		 * sanity check in am_attach(). Therefore position 0 must be
		 * the bottom limit and position 1 must be the top limit.
		 */
		ATRACE_32("am_ck_sample_rate() limits, min sr", ptr[0]);
		ATRACE_32("am_ck_sample_rate() limits, max sr", ptr[1]);
		if (sr < ptr[0] || sr > ptr[1]) {
			ATRACE("am_ck_sample_rate() limit failed", srs);
			return (AUDIO_FAILURE);
		}

		ATRACE_32("am_ck_sample_rate() found in limit", sr);
		return (AUDIO_SUCCESS);
	}

	for (; *ptr != NULL; ptr++) {
		ATRACE_32("am_ck_sample_rate() not limits, test sr", *ptr);
		if (*ptr == sr) {
			ATRACE_32("am_ck_sample_rate() found", sr);
			return (AUDIO_SUCCESS);
		}
		if (*ptr > sr) {
			ATRACE_32("am_ck_sample_rate() past", sr);
			return (AUDIO_FAILURE);
		}
	}

	ATRACE("am_ck_sample_rate() failed", cptr->ad_sr_info);

	return (AUDIO_FAILURE);

}	/* am_ck_sample_rate */

/*
 * am_safe_putnext()
 *
 * Description:
 *	The usual reason for holding a lock across putnext() is we don't
 *	want a channel to call qprocsoff() while we are building a STREAMS
 *	message. This can happen because we have many different threads,
 *	including kernel threads, that are running at the same time.
 *
 *	If the channel has called qprocsoff() then we just return.
 *
 *	CAUTION: This is only for the read queue.
 *
 * Arguments:
 *	audio_ch_t	*chptr		Pointer to this channel's state info
 *	mblk_t		*mp		Pointer to the STREAMS message to send
 *
 * Returns:
 *	void
 */
void
am_safe_putnext(audio_ch_t *chptr, mblk_t *mp)
{
	am_ch_private_t		*chpptr = chptr->ch_private;

	ATRACE("in am_safe_putnext()", chptr);

	ASSERT(MUTEX_HELD(&chptr->ch_lock));
	ASSERT(!MUTEX_HELD(&chptr->ch_statep->as_lock));

	/* make sure qprocsoff() hasn't been called */
	if (chpptr->acp_flags & AM_CHNL_QPROCSOFF) {
		/* it has, so cleanup and return */
		freemsg(mp);

		ATRACE("am_safe_putnext() msg not sent, qprocsoff()", chptr);

		return;
	}

	/* increment the number of putnext() calls outstanding */
	chpptr->acp_busy_cnt++;
	ATRACE_32("am_safe_putnext() inc acp_busy_cnt", chpptr->acp_busy_cnt);

	/* it's okay to release the lock and do the putnext() */
	mutex_exit(&chptr->ch_lock);

	putnext(RD(chptr->ch_qptr), mp);
	ATRACE("am_safe_putnext() putnext() done", chptr);

	/* now we can reaquire the lock and check to see if need to signal */
	mutex_enter(&chptr->ch_lock);

	chpptr->acp_busy_cnt--;
	ATRACE_32("am_safe_putnext() dec acp_busy_cnt", chpptr->acp_busy_cnt);

	if ((chpptr->acp_busy_cnt == 0) &&
	    (chpptr->acp_flags & AM_CHNL_SIGNAL_NEEDED)) {
		ATRACE("am_safe_putnext() sending cv_signal()", chptr);
		cv_signal(&chptr->ch_cv);
	}

	ASSERT(MUTEX_HELD(&chptr->ch_lock));
	ASSERT(!MUTEX_HELD(&chptr->ch_statep->as_lock));

}	/* am_safe_putnext() */

/*
 * am_test_canputnext()
 *
 * Description:
 *	The usual reason for holding a lock across putnext() is we don't
 *	want a channel to call qprocsoff() while we are building a STREAMS
 *	message. This can happen because we have many different threads,
 *	including kernel threads, that are running at the same time.
 *
 *	If the channel has called qprocsoff() then we just return.
 *
 *	CAUTION: This is only for the read queue.
 *
 * Arguments:
 *	audio_ch_t	*chptr		Pointer to this channel's state info
 *
 * Returns:
 *	AUDIO_SUCCESS		There is room in the next module's queue
 *	AUDIO_FAILURE		There is no room in the next module's queue
 *	AM_CHNL_CLOSED		The channel has been closed
 */
int
am_test_canputnext(audio_ch_t *chptr)
{
	am_ch_private_t		*chpptr = chptr->ch_private;
	int			room;

	ATRACE("in am_test_canputnext()", chptr);

	ASSERT(!MUTEX_HELD(&chptr->ch_lock));
	mutex_enter(&chptr->ch_lock);

	/* make sure qprocsoff() hasn't been called */
	if (chpptr->acp_flags & AM_CHNL_QPROCSOFF) {
		mutex_exit(&chptr->ch_lock);
		ATRACE("am_test_canputnext() channel closed", chptr);
		return (AM_CHNL_CLOSED);
	}

	/*
	 * Increment the number of putnext() calls outstanding,
	 * treat canputnext() like putnext().
	 */
	chpptr->acp_busy_cnt++;
	ATRACE_32("am_test_canputnext() inc acp_busy_cnt",
	    chpptr->acp_busy_cnt);

	mutex_exit(&chptr->ch_lock);

	room = canputnext(RD(chptr->ch_qptr));

	mutex_enter(&chptr->ch_lock);
	chpptr->acp_busy_cnt--;

	if ((chpptr->acp_busy_cnt == 0) &&
	    (chpptr->acp_flags & AM_CHNL_SIGNAL_NEEDED)) {
		ATRACE("am_test_canputnext() sending cv_signal()", chptr);
		cv_signal(&chptr->ch_cv);
	}
	mutex_exit(&chptr->ch_lock);

	ASSERT(!MUTEX_HELD(&chptr->ch_lock));

	if (!room) {
		ATRACE("am_test_canputnext() returning failure", chptr);
		return (AUDIO_FAILURE);
	} else {
		ATRACE("am_test_canputnext() returning success", chptr);
		return (AUDIO_SUCCESS);
	}

}	/* am_test_canputnext() */


/*
 * Private utilities used only by this file.
 */

/*
 * am_attach_check()
 *
 * Description:
 *	Verify all of the read/write parameters for the mixer. This includes
 *	making sure the format configuration is legal. We also figure out all
 *	the channel, encoding, and precision specifications and set flags. This
 *	makes things a lot faster later on.
 *
 *	NOTE: We don't set the am_hw_* members here so they'll still be set
 *		to 0 when we return. Thus the first time am_set_format() is
 *		called the hardware will be forced to be programmed.
 *
 * Arguments:
 *	am_ad_info_t	*ad_infop	Ptr to the device's capabilities struct
 *	am_apm_private_t *stpptr	Pointer to private APM data
 *	int		dir		AUDIO_PLAY or AUDIO_RECORD
 *
 * Returns:
 *	AUDIO_SUCCESS			The checks succeed
 *	AUDIO_FAILURE			The checks failed, device can't load
 */
static int
am_attach_check(audio_state_t *statep, am_ad_info_t *ad_infop,
	am_apm_private_t *stpptr, int dir)
{
	am_ad_ch_cap_t		*cptr = &ad_infop->ad_record;
	am_ad_cap_comb_t	*comb;
	audio_info_t		*hw_info = &stpptr->am_hw_info;
	audio_prinfo_t		*prinfo;
	uint_t			flags = 0;
	uint_t			mch = 0;	/* mixer channels */
	uint_t			menc = 0;	/* mixer encoding */
	uint_t			mprec = 0;	/* mixer precision */
	int			csr;		/* compat sample rate */
	int			mode;

	ATRACE("in am_attach_check()", ad_infop);
	ASSERT(statep);

	if (dir == AUDIO_PLAY) {
		ATRACE("am_attach_check() dir PLAY", 0);
		cptr = &ad_infop->ad_play;
		comb = ad_infop->ad_play_comb;
		prinfo = &ad_infop->ad_defaults->play;
	} else if (dir == AUDIO_RECORD) {
		ATRACE("am_attach_check() dir RECORD", 0);
		cptr = &ad_infop->ad_record;
		comb = ad_infop->ad_rec_comb;
		prinfo = &ad_infop->ad_defaults->record;
	} else {
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
		    "attach_check() illegal direction: %d", dir);
		return (AUDIO_FAILURE);
	}

	mode = stpptr->am_pstate->apm_mode;

	/*
	 * Check the Audio Driver capabilities for good sample rate info. For
	 * MIXER mode we get the default H/W sample rate. For COMPAT mode we
	 * verify that the default is okay.
	 *
	 * Sanity check the record COMPAT mode sample rates.
	 */
	if ((csr = am_ck_sample_rate_sanity(cptr, AM_COMPAT_MODE)) ==
	    AUDIO_FAILURE) {
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
		    "attach_check() bad COMPAT mode sample rate list");
		return (AUDIO_FAILURE);
	}

	/* make sure the default record SR for COMPAT mode is good */
	if (am_ck_sample_rate(cptr, AM_COMPAT_MODE, prinfo->sample_rate) ==
	    AUDIO_FAILURE) {
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
		    "attach_check() bad COMPAT sample rate: %d",
		    prinfo->sample_rate);
		return (AUDIO_FAILURE);
	}

	/* sanity check & find the best record MIXER mode sample rate */
	if (am_ck_sample_rate_sanity(cptr, AM_MIXER_MODE) == AUDIO_FAILURE) {
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
		    "attach_check() bad MIXER mode sample rate list");
		return (AUDIO_FAILURE);
	}
	ATRACE_32("am_attach_check() COMPAT sample rate", prinfo->sample_rate);
	ATRACE_32("am_attach_check() COMPAT max sample rate", csr);

	/*
	 * Figure out how many channel combinations we support. And also figure
	 * out the best setting for MIXER mode. We try for stereo and then
	 * settle for mono.
	 */
	if (am_ck_channels(cptr, AUDIO_CHANNELS_STEREO, B_TRUE) ==
	    AUDIO_SUCCESS) {
		flags |= AM_PRIV_CH_STEREO;
		mch = AUDIO_CHANNELS_STEREO;
	}
	if (am_ck_channels(cptr, AUDIO_CHANNELS_MONO, B_TRUE) ==
	    AUDIO_SUCCESS) {
		flags |= AM_PRIV_CH_MONO;
		if (mch == 0) {
			mch = AUDIO_CHANNELS_MONO;
		}
	}
	ATRACE_32("am_attach_check() MIXER record channels", mch);

	/* make sure we have at least one of these set */
	if (!(flags & (AM_PRIV_CH_STEREO|AM_PRIV_CH_MONO))) {
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
		    "attach_check() bad channels list");
		return (AUDIO_FAILURE);
	}

	/* make sure the COMPAT mode default channel is legal */
	if (prinfo->channels != AUDIO_CHANNELS_MONO &&
	    prinfo->channels != AUDIO_CHANNELS_STEREO) {
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
		    "attach_check() bad COMPAT record channels list");
		return (AUDIO_FAILURE);
	}
	ATRACE_32("am_attach_check() COMPAT channels", prinfo->channels);

	/*
	 * Now check all possible encoding and precision combinations and
	 * set flags to make translations easier later on. We also figure
	 * out the best settings for the mixer. We prefer 16-bit linear PCM,
	 * but we'll take whatever we can get.
	 */
	if (am_ck_combinations(comb, AUDIO_ENCODING_LINEAR, AUDIO_PRECISION_16,
	    B_TRUE) == AUDIO_SUCCESS) {
		flags |= AM_PRIV_16_PCM;
		mprec = AUDIO_PRECISION_16;
		menc = AUDIO_ENCODING_LINEAR;
	}
	if (am_ck_combinations(comb, AUDIO_ENCODING_LINEAR, AUDIO_PRECISION_8,
	    B_TRUE) == AUDIO_SUCCESS) {
		flags |= AM_PRIV_8_PCM;
		if (mprec == 0) {
			mprec = AUDIO_PRECISION_8;
			menc = AUDIO_ENCODING_LINEAR;
		}
	}
	if (am_ck_combinations(comb, AUDIO_ENCODING_LINEAR8, AUDIO_PRECISION_8,
	    B_TRUE) == AUDIO_SUCCESS) {
		flags |= AM_PRIV_8_PCM;
		if (mprec == 0) {
			mprec = AUDIO_PRECISION_8;
			menc = AUDIO_ENCODING_LINEAR8;
		}
	}
	if (am_ck_combinations(comb, AUDIO_ENCODING_ULAW, AUDIO_PRECISION_8,
	    B_TRUE) == AUDIO_SUCCESS) {
		flags |= AM_PRIV_8_ULAW;
		if (mprec == 0) {
			mprec = AUDIO_PRECISION_8;
			menc = AUDIO_ENCODING_ULAW;
		}
	}
	if (am_ck_combinations(comb, AUDIO_ENCODING_ALAW, AUDIO_PRECISION_8,
	    B_TRUE) == AUDIO_SUCCESS) {
		flags |= AM_PRIV_8_ALAW;
		if (mprec == 0) {
			mprec = AUDIO_PRECISION_8;
			menc = AUDIO_ENCODING_ALAW;
		}
	}
	ATRACE_32("am_attach_check() MIXER precision", mprec);
	ATRACE_32("am_attach_check() MIXER encoding", menc);

	/* make sure we got the mixer settings, if we didn't then bad list */
	if (mprec == 0) {
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
		    "attach_check() bad combinations list");
		return (AUDIO_FAILURE);
	}

	/* now double check a default COMPAT mode configuration */
	if (am_ck_combinations(comb, prinfo->encoding, prinfo->precision,
	    B_FALSE) == AUDIO_FAILURE) {
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
		    "attach_check() bad COMPAT combinations defaults");
		return (AUDIO_FAILURE);
	}
	ATRACE_32("am_attach_check() COMPAT precision", prinfo->precision);
	ATRACE_32("am_attach_check() COMPAT encoding", prinfo->encoding);

	/*
	 * Initialize the Codec's state. The sample rate is always set to
	 * 0 which forces am_set_format() to program the Codec the first
	 * time it is called for play and record.
	 */
	if (mode == AM_MIXER_MODE && ad_infop->ad_codec_type == AM_TRAD_CODEC) {
		if (dir == AUDIO_PLAY) {
			hw_info->play.sample_rate = 0;
			hw_info->play.channels = mch;
			hw_info->play.precision = mprec;
			hw_info->play.encoding = menc;
		} else {
			hw_info->record.sample_rate = 0;
			hw_info->record.channels = mch;
			hw_info->record.precision = mprec;
			hw_info->record.encoding = menc;
		}
	} else {
		if (dir == AUDIO_PLAY) {
			hw_info->play.sample_rate = 0;
			hw_info->play.channels = prinfo->channels;
			hw_info->play.precision = prinfo->precision;
			hw_info->play.encoding = prinfo->encoding;
		} else {
			hw_info->record.sample_rate = 0;
			hw_info->record.channels = prinfo->channels;
			hw_info->record.precision = prinfo->precision;
			hw_info->record.encoding = prinfo->encoding;
		}
	}

	/* initialize the saved state for when we go from COMPAT->MIXER mode */
	if (dir == AUDIO_PLAY) {
		/* once these get set they are set the same for life */
		stpptr->am_pflags |= flags;
		stpptr->am_save_psr = csr;
		stpptr->am_hw_pchs = mch;
		stpptr->am_hw_pprec = mprec;
		stpptr->am_hw_penc = menc;
	} else {
		/* once these get set they are set the same for life */
		stpptr->am_rflags |= flags;
		stpptr->am_save_rsr = csr;
		stpptr->am_hw_rchs = mch;
		stpptr->am_hw_rprec = mprec;
		stpptr->am_hw_renc = menc;
	}

	return (AUDIO_SUCCESS);

}	/* am_attach_check() */

/*
 * am_ck_sample_rate_sanity()
 *
 * Description:
 *	Sanity check the sample rate list to make sure it is good. That
 *	means it is ordered from smallest to largest. The largest sample
 *	rate is returned if the list is okay.
 *	AUDIO_FAILURE is returned.
 *
 *	NOTE: The sample rate conversion information is specific to the routines
 *		that perform the conversions. Therefore the audio mixer doesn't
 *		check them for sanity. It could be done by creating another
 *		call in am_ad_src_entry_t, but thorough testing is all that
 *		is really needed.
 *
 * Arguments:
 *	am_ad_ch_cap_t	*cptr	Pointer to the play/record capability struct
 *	int		mode	AM_MIXER_MODE or AM_COMPAT_MODE
 *
 * Returns:
 *	AUDIO_SUCCESS		Sample rate list okay
 *	AUDIO_FAILURE		Bad sample rate list
 */
static int
am_ck_sample_rate_sanity(am_ad_ch_cap_t *cptr, int mode)
{
	am_ad_sample_rates_t	*srs;
	uint_t			*ptr;
	uint_t			big = 0;
	int			i;

	ATRACE("in am_ck_sample_rate_sanity()", cptr);
	ATRACE_32("am_ck_sample_rate_sanity() mode", mode);

	if (mode == AM_MIXER_MODE) {
		srs = &cptr->ad_mixer_srs;
	} else {
		srs = &cptr->ad_compat_srs;
	}
	ptr = srs->ad_srs;


	/* do a sanity check on the list, it must be in increasing order */
	for (i = 0; *ptr != NULL; ptr++, i++) {
		if (*ptr > big) {
			big = *ptr;
		} else {
			ATRACE_32("am_ck_sample_rate_sanity() bad order, big",
			    big);
			ATRACE_32("am_ck_sample_rate_sanity() *ptr", *ptr);
			return (AUDIO_FAILURE);
		}
	}

	/* if limits then there should be only two samples */
	if ((srs->ad_limits & MIXER_SRS_FLAG_SR_LIMITS) && i != 2) {
		ATRACE_32("am_ck_sample_rate_sanity() "
		    "too many samples for limits", i);
		return (AUDIO_FAILURE);
	}

	ATRACE_32("am_ck_sample_rate_sanity() found highest sample rate", big);

	return (big);

}	/* am_ck_sample_rate_sanity() */

/*
 * am_convert_to_format()
 *
 * Description:
 *	This routine takes the source buffer, which is 32-bit integers,
 *	and converts it to whatever format the destination buffer is.
 *	While the source buffer is a 32-bit buffer, the data is really
 *	16-bits. We use 32-bits to make sure we can sum audio streams
 *	without loosing bits. When this routine is called we clip and
 *	then convert the data. This includes doing any required translations.
 *
 *	Other routines deal with the channel <--> channel conversion.
 *	In addition the audio is already sample rate converted, if it is
 *	needed. If the result needs to be unsigned PCM then we do that
 *	conversion.
 *
 *	The supported conversions are:
 *		32-bit signed linear	->	16-bit clipped signed linear
 *		32-bit signed linear	->	8-bit u-law
 *		32-bit signed linear	->	8-bit A-law
 *		32-bit signed linear	->	8-bit signed linear
 *
 *	We also support translating to unsigned PCM for 8-bit and 16-bit linear.
 *
 * Arguments:
 *	int		*src		Ptr to the src buffer, data to convert
 *	void		*dest		Ptr to the dest buffer, for converted
 *					data
 *	int		samples		The number of samples to convert
 *	int		precision	The precision of the output buffer
 *	int		encoding	The encoding of the output buffer
 *	int		flags		Flags, including AM_PRIV_8/16_TRANS
 *
 * Returns:
 *	none
 */
static void
am_convert_to_format(int *src, void *dest, int samples, int precision,
	int encoding, int flags)
{
	int		val;

	ATRACE_32("in am_convert_to_format()", samples);
	ATRACE_32("am_convert_to_format() precision", precision);
	ATRACE_32("am_convert_to_format() encoding", encoding);

	/* this should have been stopped earlier */
	ASSERT(precision != AUDIO_PRECISION_16 ||
	    encoding == AUDIO_ENCODING_LINEAR);

	/* make sure we have work to do */
	if (samples == 0) {
		ATRACE("am_convert_to_format() "
		    "no samples to convert, returning", 0);
		return;
	}

	ATRACE_32("am_convert_to_format() NON-Linearize Audio", samples);

	if (precision == AUDIO_PRECISION_16) {
		int16_t	*dptr = (int16_t *)dest;

		ASSERT(encoding == AUDIO_ENCODING_LINEAR);

		if (flags & AM_PRIV_16_TRANS) {
			/* convert for unsigned int hardware */
			for (; samples--; ) {
				val = *src++;
				if (val > INT16_MAX) {
					val = INT16_MAX;
				} else if (val < INT16_MIN) {
					val  = INT16_MIN;
				}
				val += -INT16_MIN;
				*dptr++ = (int16_t)val;
			}
		} else {
			/* hardware is signed */
			for (; samples--; ) {
				val = *src++;
				if (val > INT16_MAX) {
					*dptr++ = INT16_MAX;
				} else if (val < INT16_MIN) {
					*dptr++ = INT16_MIN;
				} else {
					*dptr++ = (int16_t)val;
				}
			}
		}
		ATRACE("am_convert_to_format() 16-bit linear done", 0);
	} else {	/* end 16-bit, begin 8-bit */
		uint8_t		*dptr = (uint8_t *)dest;

		ASSERT(precision == AUDIO_PRECISION_8);

		if (encoding == AUDIO_ENCODING_LINEAR8 ||
		    (flags & AM_PRIV_8_TRANS)) {
			ATRACE_32(
			    "am_convert_to_format() 8-bit unsigned linear",
			    samples);

			for (; samples--; ) {
				val = *src++;
				if (val > INT16_MAX) {
					val = INT16_MAX;
				} else if (val < INT16_MIN) {
					val = INT16_MIN;
				}
				*dptr++ = (uint8_t)((val >> AM_256_SHIFT) -
				    INT8_MAX);
			}
		} else if (encoding == AUDIO_ENCODING_LINEAR) {
			ATRACE_32("am_convert_to_format() 8-bit signed linear",
			    samples);

			for (; samples--; ) {
				val = *src++;
				if (val > INT16_MAX) {
					val = INT16_MAX;
				} else if (val < INT16_MIN) {
					val = INT16_MIN;
				}
				*dptr++ = (uint8_t)(val >> AM_256_SHIFT);
			}
		} else {	/* 8-bit U/A-Law */
			uint8_t		*cptr;
			int		shift;

			if (encoding == AUDIO_ENCODING_ULAW) {
				ATRACE("am_convert_to_format() 8-bit U-Law", 0);
				cptr = &_14linear2ulaw8[G711_ULAW_MIDPOINT];
				shift = 2;
			} else {
				ATRACE("am_convert_to_format() 8-bit A-Law", 0);
				ASSERT(encoding == AUDIO_ENCODING_ALAW);
				cptr = &_13linear2alaw8[G711_ALAW_MIDPOINT];
				shift = 3;
			}

			ATRACE_32("am_convert_to_format() 8-bit U/A-Law",
			    encoding);

			for (; samples--; ) {
				val = *src++;
				if (val > INT16_MAX) {
					val = INT16_MAX;
				} else if (val < INT16_MIN) {
					val = INT16_MIN;
				}
				*dptr++ = (uint8_t)cptr[val >> shift];
			}
		}
		ATRACE("am_convert_to_format() 8-bit done", 0);
	}

	ATRACE_32("am_convert_to_format() done", encoding);

}	/* am_convert_to_format() */

/*
 * am_get_audio_multi()
 *
 * Description:
 *	This routine is used by multi-channel Codecs to get a single stream
 *	of audio data for an individual channel.
 *
 * Arguments:
 *	audio_state_t	*statep		Pointer to the device instance's state
 *	void		*buf		The buffer to place the audio into
 *	int		channel		The device channel number.
 *	int		samples		The number of samples to get
 *
 *	NOTE: The variable "samples" is the number of samples the hardware
 *		wants. So it is samples at the hardware's sample rate.
 *
 * Returns:
 *	>= 0			The number of samples transferred to the buffer
 *	AUDIO_FAILURE		An error has occurred
 */
static int
am_get_audio_multi(audio_state_t *statep, void *buf, int channel, int samples)
{
	audio_ch_t		*chptr = &statep->as_channels[channel];
	am_ch_private_t		*chpptr;
	audio_info_t		*info;
	int			hw_channels;
	int			ret_val;

	ATRACE("in am_get_audio_multi()", statep);

	ASSERT(statep);
	ASSERT(chptr->ch_info.ch_number == channel);

	/* lock the channel before we check it out */
	mutex_enter(&chptr->ch_lock);

	/*
	 * The channel may have been closed while we waited on the mutex.
	 * So once we get it we make sure the channel is still valid. We also
	 * make sure it's an AUDIO channel.
	 */
	chpptr = chptr->ch_private;
	info = chptr->ch_info.info;

	if (!(chptr->ch_flags & AUDIO_CHNL_ALLOCATED) ||
	    chptr->ch_info.pid == 0 || chptr->ch_info.dev_type != AUDIO ||
	    chpptr == NULL || ((chpptr->acp_flags & AM_CHNL_OPEN) == 0) ||
	    (chpptr->acp_flags & AM_CHNL_QPROCSOFF) || info == NULL) {
		mutex_exit(&chptr->ch_lock);
		ATRACE("am_get_audio_multi() channel closed", chptr);
		return (AUDIO_FAILURE);
	}

	/* skip if the channel is paused */
	if (info->play.pause) {
		mutex_exit(&chptr->ch_lock);
		ATRACE("am_get_audio_multi() channel paused", statep);
		return (0);
	}

	/* make sure the number of samples is module the # of channels */
	hw_channels = info->play.channels;
	if (hw_channels != AUDIO_CHANNELS_MONO &&
	    (samples % hw_channels) != 0) {
		ATRACE_32("am_get_audio_multi() bad sample size", samples);
		samples -= samples % hw_channels;
	}

	/* get "samples" worth of data */
	ATRACE("am_get_audio_multi() calling am_get_samples()", chptr);
	chpptr->acp_busy_cnt++;
	ret_val = am_get_samples(chptr, samples, buf, AM_COMPAT_MODE);
	chpptr->acp_busy_cnt--;
	if (ret_val == AUDIO_FAILURE || ret_val == 0) {
		am_audio_drained(chptr);
		ATRACE_32("am_get_audio_multi() am_get_samples() failed",
		    ret_val);
		goto done;
	}

	ATRACE_32("am_get_audio_multi() am_get_samples() succeeded", ret_val);

	/* XXX we need to convert to the hardware format */

done:
	if ((chpptr->acp_busy_cnt == 0) &&
	    (chpptr->acp_flags & AM_CHNL_SIGNAL_NEEDED)) {
		ATRACE("am_get_audio_multi() sending cv_signal()", chptr);
		cv_signal(&chptr->ch_cv);
	}

	mutex_exit(&chptr->ch_lock);

	ATRACE("am_get_audio_multi() done", buf);

	return (ret_val);

}	/* am_get_audio_multi() */

/*
 * am_get_audio_trad_compat()
 *
 * Description:
 *	This routine is used by traditional Codecs in COMPAT mode. The
 *	audio samples are placed directly into the buffer provided by the
 *	Audio Driver. Once one playing channel is found the search ends,
 *	no reason to waste more time.
 *
 *	CAUTION: This routine is called from interrupt context, so memory
 *		allocation cannot sleep.
 *
 * Arguments:
 *	audio_state_t		*statep		Ptr to the dev instances' state
 *	audio_apm_info_t	*apm_infop	Personality module data struct
 *	void			*buf		The buf to place the audio into
 *	int			samples		The number of samples to get
 *
 *	NOTE: The variable "samples" is the number of samples the hardware
 *		wants. So it is samples at the hardware's sample rate.
 *
 * Returns:
 *	>= 0			The number of samples transferred to the buffer
 *	AUDIO_FAILURE		An error has occurred
 */
static int
am_get_audio_trad_compat(audio_state_t *statep, audio_apm_info_t *apm_infop,
	void *buf, int samples)
{
	audio_ch_t		*chptr;
	audio_info_t		*info;
	am_ch_private_t		*chpptr;
	am_apm_private_t	*stpptr = apm_infop->apm_private;
	int			i;
	int			max_chs;
	int			ret_val;
	size_t			size = samples << AM_INT32_SHIFT;

	ATRACE("in am_get_audio_trad_compat()", statep);

	ASSERT(statep);

	/* get the number of chs for this instance */
	max_chs = statep->as_max_chs;

	/* go through the chs looking for the only playing AUDIO ch */
	for (i = 0, chptr = &statep->as_channels[0];
	    i < max_chs; i++, chptr++) {

		/* lock the channel before we check it out */
		mutex_enter(&chptr->ch_lock);

		/* skip non-AUDIO and unallocated channels */
		if (!(chptr->ch_flags & AUDIO_CHNL_ALLOCATED) ||
		    chptr->ch_info.dev_type != AUDIO ||
		    chptr->ch_info.pid == 0) {

			mutex_exit(&chptr->ch_lock);
			continue;
		}

		/* make sure this channel is valid */
		chpptr = chptr->ch_private;
		info = chptr->ch_info.info;
		if (chpptr == NULL || info == NULL ||
		    (chpptr->acp_flags & AM_CHNL_OPEN) == 0) {
			mutex_exit(&chptr->ch_lock);
			ATRACE("am_get_audio_trad_compat() channel closed",
			    chptr);
			continue;
		}

		/* make sure this channel is writing */
		if (!chpptr->acp_writing) {
			ATRACE("am_get_audio_trad_compat() not playing",
			    chpptr);
			mutex_exit(&chptr->ch_lock);
			continue;
		}

		/* skip paused AUDIO channels */
		if (info->play.pause) {
			mutex_exit(&chptr->ch_lock);
			return (0);
		}

		mutex_exit(&chptr->ch_lock);

		ATRACE_32("am_get_audio_trad_compat() found channel", i);
		break;
	}
	if (i >= max_chs) {
		ATRACE("am_get_audio_trad_compat() done, no play channel", buf);
		return (0);
	}

	mutex_enter(&chptr->ch_lock);

	/*
	 * We had to free the lock above to make warlock happy. Unfortunately
	 * it's possible that the channel closed between releasing and
	 * reacquiring the lock. So we have to check again.
	 */
	if (!(chptr->ch_flags & AUDIO_CHNL_ALLOCATED) ||
	    chptr->ch_info.dev_type != AUDIO || chptr->ch_info.pid == 0 ||
	    chpptr == NULL || (chpptr->acp_flags & AM_CHNL_QPROCSOFF)) {
		mutex_exit(&chptr->ch_lock);
		ATRACE("am_get_audio_trad_compat() ch closed on us", chptr);
		return (0);
	}

	/* make sure the buffer is big enough */
	if (chpptr->acp_psb_size < size) {
		ATRACE_32("am_get_audio_trad_compat() freeing buffer",
		    chpptr->acp_psb_size);
		if (chpptr->acp_play_samp_buf) {
			/* free the old buffer */
			kmem_free(chpptr->acp_play_samp_buf,
			    chpptr->acp_psb_size);
		}
		chpptr->acp_play_samp_buf = kmem_alloc(size, KM_NOSLEEP);
		if (chpptr->acp_play_samp_buf == NULL) {
			ATRACE_32("am_get_audio_trad_compat() "
			    "kmem_alloc() play_samp_buf failed", i);
			audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN,
			    "am_get_audio_trad_compat() "
			    "sample buffer %d not allocated", i);
			chpptr->acp_psb_size = 0;
			mutex_exit(&chptr->ch_lock);
			return (0);
		}
		chpptr->acp_psb_size = size;
	}

	ATRACE_32("am_get_audio_trad_compat() calling am_get_samples()",
	    samples);

	chpptr->acp_busy_cnt++;
	ret_val = am_get_samples(chptr, samples, chpptr->acp_play_samp_buf,
	    AM_COMPAT_MODE);
	chpptr->acp_busy_cnt--;

	ATRACE_32("am_get_audio_trad_compat() am_get_samples() succeeded",
	    ret_val);

	/* now we can see how well the am_get_samples() call did */
	if (ret_val == AUDIO_FAILURE || ret_val == 0) {
		am_audio_drained(chptr);
		ATRACE_32("am_get_audio_trad_compat() am_get_samples() failed",
		    ret_val);
		goto done;
	}

	/* now convert to the format the audio device uses */
	am_convert_to_format(chpptr->acp_play_samp_buf, buf, ret_val,
	    stpptr->am_hw_pprec, stpptr->am_hw_penc, stpptr->am_pflags);

done:
	if ((chpptr->acp_busy_cnt == 0) &&
	    (chpptr->acp_flags & AM_CHNL_SIGNAL_NEEDED)) {
		ATRACE("am_get_audio_trad_compat() sending cv_signal()", chptr);
		cv_signal(&chptr->ch_cv);
	}

	/* we can free the lock now */
	mutex_exit(&chptr->ch_lock);

	ATRACE("am_get_audio_trad_compat() done", buf);

	return (ret_val);

}	/* am_get_audio_trad_compat() */

/*
 * am_get_audio_trad_mixer()
 *
 * Description:
 *	This routine is used by traditional Codecs in MIXER mode to get
 *	multiple streams of audio data and mixing them down into one stream
 *	for the Codec. play_samp_buf is used to get audio samples. These
 *	samples are then mixed into the mix buffer. When all playing audio
 *	channels are mixed we convert to the proper output format, along with
 *	applying gain and balance, if needed.
 *
 *	CAUTION: This routine is called from interrupt context, so memory
 *		allocation cannot sleep.
 *
 * Arguments:
 *	audio_state_t		*statep		Ptr to the dev instances' state
 *	audio_apm_info_t	*apm_infop	Personality module data struct
 *	void			*buf		The buf to place the audio into
 *	int			samples		The number of samples to get
 *
 *	NOTE: The variable "samples" is the number of samples the hardware
 *		wants. So it is samples at the hardware's sample rate.
 *
 * Returns:
 *	>= 0			The number of samples transferred to the buffer
 *	AUDIO_FAILURE		An error has occurred
 */
static int
am_get_audio_trad_mixer(audio_state_t *statep, audio_apm_info_t *apm_infop,
	void *buf, int samples)
{
	audio_ch_t		*chptr;
	audio_info_t		*info;
	am_apm_private_t	*stpptr = apm_infop->apm_private;
	audio_info_t		*hw_info;
	am_ch_private_t		*chpptr;
	int			*mix_dest;
	int			*mix_src;
	size_t			size = samples << AM_INT32_SHIFT;
	uint_t			hw_channels = stpptr->am_hw_pchs;
	int			balance;
	int			i;
	int			l_gain;
	int			r_gain;
	int			max_chs;
	int			max_ret_val = 0;
	int			ret_val;

	ATRACE("in am_get_audio_trad_mixer()", statep);
	ATRACE_32("am_get_audio_trad_mixer() samples", samples);
	ASSERT(statep);

	/* get the number of chs for this instance */
	max_chs = statep->as_max_chs;

	hw_info = apm_infop->apm_ad_state;

	/* make sure the mix buffer is large enough */
	if (stpptr->am_mix_size < size) {
		/* mix buffer too small, adjust sample request */
		ATRACE_32("am_get_audio_trad_mixer() mix buffer too small",
		    stpptr->am_mix_size);
		ATRACE_32("am_get_audio_trad_mixer() adjust num samples from",
		    samples);
		samples = stpptr->am_mix_size >> AM_INT32_SHIFT;
		ATRACE_32("am_get_audio_trad_mixer() num samples now set to",
		    samples);
	}

	/* zero the mix buffer, no reason to zero the whole buffer */
	bzero(stpptr->am_mix_buf, size);

	/* go through the chs looking for each AUDIO ch */
	for (i = 0, chptr = &statep->as_channels[0];
	    i < max_chs; i++, chptr++) {

		/* lock the channel before we check it out */
		mutex_enter(&chptr->ch_lock);

		/* skip non-AUDIO and unallocated channels */
		if (!(chptr->ch_flags & AUDIO_CHNL_ALLOCATED) ||
		    (chptr->ch_info.dev_type != AUDIO) ||
		    (chptr->ch_info.pid == 0)) {
			mutex_exit(&chptr->ch_lock);
			continue;
		}

		/* make sure this channel is valid */
		chpptr = chptr->ch_private;
		info = chptr->ch_info.info;

		if (chpptr == NULL || info == NULL ||
		    (chpptr->acp_flags & AM_CHNL_QPROCSOFF) ||
		    (!chpptr->acp_writing)) {
			mutex_exit(&chptr->ch_lock);
			ATRACE("am_get_audio_trad_mixer() not valid", chpptr);
			continue;
		}

		/* skip paused AUDIO channels */
		if (info->play.pause) {
			mutex_exit(&chptr->ch_lock);
			continue;
		}

		ATRACE_32("am_get_audio_trad_mixer() found channel", i);

		info = chptr->ch_info.info;

		/* make sure the buffer is big enough */
		if (chpptr->acp_psb_size < size) {

			ATRACE_32("am_get_audio_trad_mixer() freeing buffer",
			    chpptr->acp_psb_size);
			if (chpptr->acp_play_samp_buf) {
				/* free the old buffer */
				kmem_free(chpptr->acp_play_samp_buf,
				    chpptr->acp_psb_size);
			}
			chpptr->acp_play_samp_buf =
			    kmem_alloc(size, KM_NOSLEEP);
			if (chpptr->acp_play_samp_buf == NULL) {
				ATRACE_32("am_get_audio_trad_mixer() "
				    "kmem_alloc() play_samp_buf failed", i);
				audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN,
				    "am_get_audio_trad_mixer() "
				    "sample buffer %d not allocated", i);
				chpptr->acp_psb_size = 0;
				mutex_exit(&chptr->ch_lock);
				continue;
			}
			chpptr->acp_psb_size = size;
		}

		/* get "samples" worth of audio */
		ATRACE_32("am_get_audio_trad_mixer() calling am_get_samples()",
		    samples);

		chpptr->acp_busy_cnt++;
		ret_val = am_get_samples(chptr, samples,
		    chpptr->acp_play_samp_buf, AM_MIXER_MODE);
		chpptr->acp_busy_cnt--;

		ATRACE_32("am_get_audio_trad_mixer() "
		    "am_get_samples() succeeded", ret_val);

		/* now we can see how well the am_get_samples() call did */
		if (ret_val == AUDIO_FAILURE || ret_val == 0) {
			am_audio_drained(chptr);
			mutex_exit(&chptr->ch_lock);
			ATRACE_32("am_get_audio_trad_mixer() "
			    "am_get_samples() failed", ret_val);
			continue;
		}


		/* we return the maximum # of samples found & processed */
		if (ret_val > max_ret_val) {
			/* update to a new value */
			max_ret_val = ret_val;
			ATRACE_32("am_get_audio_trad_mixer() "
			    "updated max_ret_val", max_ret_val);
		}

		/* mix this channel into the mix buffer */
		mix_src = chpptr->acp_play_samp_buf;
		mix_dest = stpptr->am_mix_buf;
		ATRACE("am_get_audio_trad_mixer() mix_src before", mix_src);
		ATRACE("am_get_audio_trad_mixer() mix_dest before", mix_dest);
		/* apply gain and balance while summing */
		if (hw_channels == AUDIO_CHANNELS_MONO) {
			l_gain = info->play.gain;

			for (; ret_val; ret_val--) {
				*mix_dest++ +=
				    (*mix_src++ * l_gain) >> AM_MAX_GAIN_SHIFT;
			}
		} else {
			ASSERT(hw_channels == AUDIO_CHANNELS_STEREO);

			l_gain = r_gain = info->play.gain;
			balance = info->play.balance;

			if (balance < AUDIO_MID_BALANCE) {
				/* leave l gain alone and scale down r gain */
				r_gain = (r_gain * balance) >> 5;
			} else if (balance > AUDIO_MID_BALANCE) {
				/* leave r gain alone and scale down l gain */
				l_gain = (l_gain * (64 - balance)) >> 5;
			}

			for (; ret_val; ret_val -= 2) {
				*mix_dest++ +=
				    (*mix_src++ * l_gain) >> AM_MAX_GAIN_SHIFT;
				*mix_dest++ +=
				    (*mix_src++ * r_gain) >> AM_MAX_GAIN_SHIFT;
			}
		}

		if ((chpptr->acp_busy_cnt == 0) &&
		    (chpptr->acp_flags & AM_CHNL_SIGNAL_NEEDED)) {
			ATRACE("am_get_audio_trad_mixer() sending cv_signal()",
			    chptr);
			cv_signal(&chptr->ch_cv);
		}

		/* we can free the lock now */
		mutex_exit(&chptr->ch_lock);

		ATRACE("am_get_audio_trad_mixer() mix_src after", mix_src);
		ATRACE("am_get_audio_trad_mixer() mix_dest after", mix_dest);

		ATRACE_32("am_get_audio_trad_mixer() ret_val", ret_val);
		ATRACE_32("am_get_audio_trad_mixer() max_ret_val", max_ret_val);

		ATRACE("am_get_audio_trad_mixer() going again", chptr);
	}

	/* now convert into the format the hardware needs */
	ATRACE("am_get_audio_trad_mixer() calling am_convert_to_format()",
	    stpptr->am_mix_buf);
	am_convert_to_format(stpptr->am_mix_buf, buf, max_ret_val,
	    stpptr->am_hw_pprec, stpptr->am_hw_penc, stpptr->am_pflags);

	/* update hardware sample count */
	hw_info->play.samples += max_ret_val / stpptr->am_hw_pchs;

	ATRACE("am_get_audio_trad_mixer() done", buf);

	return (max_ret_val);

}	/* am_get_audio_trad_mixer() */

/*
 * am_get_samples()
 *
 * Description:
 *	This routine takes the first message off the channel's queue. It
 *	then takes audio data until the requested number of samples has
 *	been reached or there are no more samples. If the message isn't
 *	empty it is put back onto the message queue.
 *
 *	If the channel is muted then the requested number of samples is
 *	updated in the buffer, the pointer for the message is advanced and
 *	the buffer is zeroed, filling it with silence.
 *
 *	If the "mode" argument is set to AM_COMPAT_MODE then the data size
 *	is set by the channel's info structure. Otherwise it is set to the
 *	size of an integer. Because multi-stream devices get raw data,
 *	am_get_audio_multi() calls this with AM_COMPAT_MODE set.
 *
 *	Keeping track of samples is complicated. When a complete message has
 *	been played info->play.samples is incremented by the number of sample
 *	frames in the original message. That way we don't build up errors by
 *	approximating the sample rate converted sample frames. As each chunk
 *	of samples is retrieved to be played we add this amount to
 *	acp_psamples_c, the running count. Then the next time that this routine
 *	is called the amount in acp_psamples_c is added to acp_psamples_p,
 *	the partial count. This causes the delay between when the samples
 *	are placed into the buffer and when it is actually played.
 *	acp_psamples_p is used by am_fix_info() to adjust info->play.samples
 *	in between full messages, including for sample rate conversion.
 *
 *	No conversions are done in this routine.
 *
 *	CAUTION: The channel must be locked before this routine is called.
 *
 *	NOTE: The variable "samples" is the number of samples returned
 *		ultimately to the hardware.
 *
 * Arguments:
 *	audio_ch_t	*chptr		Pointer to the channel's state structure
 *	int		samples		The number of samples to get
 *	void		*buf		The buffer to put the samples into
 *	int		mode		Mixer mode
 *
 * Returns:
 *	0 -> samples			The number of samples retrieved
 *	AUDIO_FAILURE			There was an error getting samples
 */
static int
am_get_samples(audio_ch_t *chptr, int samples, void *buf, int mode)
{
	audio_state_t		*statep = chptr->ch_statep;
	audio_data_t		*data;
	am_ad_info_t		*ad_infop = chptr->ch_apm_infop->apm_ad_infop;
	am_ch_private_t		*chpptr = chptr->ch_private;
	am_apm_private_t	*stpptr = chptr->ch_apm_infop->apm_private;
	audio_info_t		*hw_info = &stpptr->am_hw_info;
	audio_info_t		*info = chptr->ch_info.info;
#ifdef FLOW_CONTROL
	queue_t			*q;
#endif
	size_t			orig_size;
	int			*bptr = buf;
	int			*eptr;
	int			*pstart;
	int			*sptr;
	boolean_t		active_signal = B_FALSE;
	boolean_t		empty = B_FALSE;
	boolean_t		mute;
	boolean_t		EOF_processed = B_FALSE;
	uint_t			ret_samples = 0;
	int			bytes_needed;
	int			count;
	int			EOF_count;
	int			hw_channels = stpptr->am_hw_pchs;

	ATRACE("in am_get_samples()", chptr);
	ATRACE_32("am_get_samples() samples", samples);
	ATRACE("am_get_samples() buffer", buf);

	ASSERT(statep);
	ASSERT(MUTEX_HELD(&chptr->ch_lock));

	/* do this now where it's easier */
	mute = info->output_muted;
	if (mute) {
		/* we return zeros */
		bytes_needed = samples << AM_INT32_SHIFT;
		ATRACE("am_get_samples() bzero", buf);
		bzero(buf, bytes_needed);
	}

	/* update played samples */
	if (chpptr->acp_psamples_f) {
		chpptr->acp_psamples_p = 0;
	}

	info->play.samples += chpptr->acp_psamples_f;
	chpptr->acp_psamples_p += chpptr->acp_psamples_c;

	chpptr->acp_psamples_f = 0;
	chpptr->acp_psamples_c = 0;

	/* go through as many buffers as we need to get the samples */
	for (; samples > 0; ) {
		if (!(chpptr->acp_flags & AM_CHNL_OPEN)) {
			ATRACE_32("am_get_samples() not open",
			    chpptr->acp_flags);
			return (0);
		}

		/* get the data off the list */
		data = audio_sup_get_audio_data(chptr);

#ifdef FLOW_CONTROL
		/*
		 * See if we should re-enable the queue. We do this now
		 * because we always need to do it and the code branches below.
		 */
		ASSERT(MUTEX_HELD(&chptr->ch_lock));
		if ((chpptr->acp_flags & AM_CHNL_PFLOW) &&
		    (audio_sup_get_audio_data_size(chptr) <
		    (AM_MIN_QUEUED_MSGS_SIZE) &&
		    audio_sup_get_audio_data_cnt(chptr) <
		    AM_MIN_QUEUED_MSGS_CNT)) {
			/* yes, re-enable the q */
			chpptr->acp_flags &= ~AM_CHNL_PFLOW;

			q = WR(chptr->ch_qptr);

			ATRACE("am_get_samples() flow control disabled, q on",
			    q);

			enableok(q);
			qenable(q);
		}
#endif

		/* now we see if we got any data */
		if (data == NULL) {
			ATRACE("am_get_samples() no data", chptr);
			/* we underflowed, so up error count and send signal */

			mutex_enter(&chptr->ch_apm_infop->apm_lock);

			if (!(chpptr->acp_flags &
			    (AM_CHNL_EMPTY|AM_CHNL_ALMOST_EMPTY1)) &&
			    !(stpptr->am_flags & AM_PRIV_SW_MODES)) {
				/* but only send it one time */
				info->play.error = 1;
				empty = B_TRUE;
			}
			mutex_exit(&chptr->ch_apm_infop->apm_lock);

			/* did we get any audio at all? */
			ATRACE_32("am_get_samples() ret_samples", ret_samples);
			if (ret_samples == 0) {
			    ATRACE("am_get_samples() no data returning", chptr);

				/*
				 * Marking the channel as empty is a two step
				 * process because data is queued up and still
				 * being played the first time we determine we
				 * are empty. So the first time we set
				 * ALMOST_EMPTY. The second time we set EMPTY.
				 */
			    if (!(chpptr->acp_flags & (AM_CHNL_ALMOST_EMPTY1|
				AM_CHNL_ALMOST_EMPTY2|AM_CHNL_EMPTY))) {

				chpptr->acp_flags |= AM_CHNL_ALMOST_EMPTY1;
				ATRACE("am_get_samples() no data empty1",
				    chpptr->acp_flags);
			    } else if
				((chpptr->acp_flags & AM_CHNL_ALMOST_EMPTY1)) {

				chpptr->acp_flags &= ~AM_CHNL_ALMOST_EMPTY1;
				chpptr->acp_flags |= AM_CHNL_ALMOST_EMPTY2;
				ATRACE("am_get_samples() no data empty2",
				    chpptr->acp_flags);
			    } else {
				ASSERT(chpptr->acp_flags &
				    (AM_CHNL_ALMOST_EMPTY2|AM_CHNL_EMPTY));
				chpptr->acp_flags &= ~(AM_CHNL_ALMOST_EMPTY1|\
				    AM_CHNL_ALMOST_EMPTY2|\
				    AM_CHNL_DRAIN_NEXT_INT|AM_CHNL_DRAIN);
				chpptr->acp_flags |= AM_CHNL_EMPTY;
				ATRACE("am_get_samples() no data empty",
				    chpptr->acp_flags);
				if (info->play.active) {
					active_signal = B_TRUE;
					info->play.active = 0;
				}
			    }
			    goto done_getting_samples;
			}
			ATRACE_32("am_get_samples() no data but samps",
			    ret_samples);
			goto done_getting_samples;
		}

		mutex_enter(&chptr->ch_apm_infop->apm_lock);
		/*
		 * See if we need to change modes. The following code makes
		 * sure that this switch happens on a message boundary.
		 *
		 * It should be noted that it is possible to pause the
		 * channel and then switch modes. Because pause may last
		 * a long time we don't block the mode switch. When paused
		 * it is very likely that we will not be on a message
		 * boundary. If setting to mixer mode it is the responsibility
		 * of the mode switch code to perform the sample rate
		 * conversion of canonical audio and then set the pointers
		 * to the approximate location for restarting, if setting
		 * to mixer mode. It is also likely that there are additional
		 * unprocessed messages. Code below will process each of
		 * these as they come up.
		 */
		if (stpptr->am_flags & AM_PRIV_SW_MODES &&
		    ((mode == AM_MIXER_MODE && data->adata_proc &&
		    data->adata_pptr == data->adata_proc) ||
		    (mode == AM_COMPAT_MODE && data->adata_orig &&
		    data->adata_optr == data->adata_orig))) {
			mutex_exit(&chptr->ch_apm_infop->apm_lock);

			ASSERT(ad_infop->ad_codec_type == AM_TRAD_CODEC);

			audio_sup_putback_audio_data(chptr, data);

			ATRACE("am_get_samples() AM_PRIV_SW_MODES return", 0);

			goto done_getting_samples;
		}
		mutex_exit(&chptr->ch_apm_infop->apm_lock);

		/* check for EOF message, i.e., zero length buffer */
		if (data->adata_osize == 0) {
			ATRACE_32("am_get_samples() EOF",
			    chpptr->acp_EOF[chpptr->acp_EOF_toggle]);

			chpptr->acp_EOF[chpptr->acp_EOF_toggle]++;

			EOF_processed = B_TRUE;

			ATRACE_32("am_get_samples() EOF, new count",
			    chpptr->acp_EOF[chpptr->acp_EOF_toggle]);

			audio_sup_free_audio_data(data);
			continue;
		}

		ATRACE("am_get_samples() got data", data);

		/*
		 * We may have changed modes or a previous attempt to process
		 * the audio data failed. This gives us a second chance before
		 * we have to throw the audio away.
		 */
		if (mode == AM_MIXER_MODE && data->adata_proc == NULL &&
		    ad_infop->ad_codec_type == AM_TRAD_CODEC) {
			ATRACE("am_get_samples(M) calling am_reprocess()",
			    data);

			/* if set to 0 then we've got a problem */
			if (data->adata_osize == 0) {
				ATRACE_32("am_get_samples(M) bad osize",
				    data->adata_osize);
				audio_sup_free_audio_data(data);
				continue;
			}

			/* process the original data into src data */
			if (am_reprocess(chptr, data) == AUDIO_FAILURE) {
				audio_sup_log(AUDIO_STATE2HDL(statep),
				    CE_NOTE, "get_samples() "
				    "couldn't process message, data lost");
				audio_sup_free_audio_data(data);
				continue;
			}
			ATRACE("am_get_samples() process successful", data);
		}

		/*
		 * Get the size of the original data, in sample frames.
		 * First convert from bytes to samples, then adjust for
		 * the number of channels.
		 */
		orig_size = (data->adata_osize >> AM_INT32_SHIFT) / hw_channels;

		/* get the right buffer */
		if (mode == AM_MIXER_MODE &&
		    ad_infop->ad_codec_type == AM_TRAD_CODEC) {
			pstart = data->adata_pptr;
			eptr = data->adata_peptr;
		} else {
			ASSERT(mode == AM_COMPAT_MODE ||
			    ad_infop->ad_codec_type == AM_MS_CODEC);
			pstart = data->adata_optr;
			eptr = data->adata_oeptr;
		}

		ATRACE("am_get_samples() beginning eptr", eptr);
		ATRACE_32("am_get_samples() samples needed", samples);

		/* get the data from the message and put into the buf */

		sptr = pstart;
		ASSERT(sptr >= pstart);
		ATRACE("am_get_samples() beginning sptr", sptr);

		if (mute == B_TRUE) {
			/* we already zeroed the buffer above */
			if ((eptr - sptr) < samples) {
				count = eptr - sptr;
				samples -= count;
				sptr = eptr;
				ASSERT(samples > 0);
			} else {
				count = samples;
				samples = 0;
				sptr += count;
				ASSERT(sptr <= eptr);
			}
		} else {
			/* copy into the buffer */
			for (count = 0; sptr < eptr && samples > 0;
			    samples--, count++) {
				*bptr++ = *sptr++;
			}
		}

		ATRACE("am_get_samples() ending sptr", sptr);
		ATRACE_32("am_get_samples() ending samples needed", samples);
		ATRACE_32("am_get_samples() ending count", count);

		ASSERT(sptr <= eptr);
		ret_samples += count;

		ATRACE_32("am_get_samples() ret_samples #2", ret_samples);

		/* see if we need to go again */
		if (samples == 0) {	/* nope */
			/* see if we're done with this message */
			if (sptr >= eptr) {
				ASSERT(sptr == eptr);
				/* update sample counts */
				chpptr->acp_psamples_f += orig_size;
				chpptr->acp_psamples_c = 0;

				/* end of data, so free */
				audio_sup_free_audio_data(data);
				data = NULL;
			} else {	/* nope, use again next time */
				pstart = sptr;
				chpptr->acp_psamples_c += count / hw_channels;
			}
			break;
		} else {
			chpptr->acp_psamples_f += orig_size;
			chpptr->acp_psamples_c = 0;
		}
		/* we need to go again, but free data first */
		audio_sup_free_audio_data(data);
		buf = bptr;	/* save for next go around */

	}	/* get buffers for() loop */

	/* update pointers, if partial buffer used */
	if (data) {
		if (mode == AM_MIXER_MODE &&
		    ad_infop->ad_codec_type == AM_TRAD_CODEC) {
			/* update the processed data pointer */
			data->adata_pptr = pstart;
		} else {
			/* update the original data pointer */
			data->adata_optr = pstart;
		}
		audio_sup_putback_audio_data(chptr, data);
	}

done_getting_samples:

	/* see if we need to send any EOF signals */
	AUDIO_TOGGLE(chpptr->acp_EOF_toggle);
	EOF_count = 0;
	if (chpptr->acp_EOF[chpptr->acp_EOF_toggle]) {
		EOF_count += chpptr->acp_EOF[chpptr->acp_EOF_toggle];
		chpptr->acp_EOF[chpptr->acp_EOF_toggle] = 0;
	}

	/*
	 * If all we have are EOFs then we need to flush the EOF count.
	 * This is done in am_wsvc() as well. This way the EOF count is
	 * incremented as soon as it can be detected.
	 */
	if (audio_sup_get_audio_data_cnt(chptr) == 0 && !hw_info->play.active) {
		AUDIO_TOGGLE(chpptr->acp_EOF_toggle);
		if (chpptr->acp_EOF[chpptr->acp_EOF_toggle]) {
			EOF_count += chpptr->acp_EOF[chpptr->acp_EOF_toggle];
			chpptr->acp_EOF[chpptr->acp_EOF_toggle] = 0;
		}

		/* if all we had was EOFs then we really are empty */
		if (EOF_processed && ret_samples == 0) {
			chpptr->acp_flags &= ~(AM_CHNL_ALMOST_EMPTY1|\
			    AM_CHNL_ALMOST_EMPTY2);
			chpptr->acp_flags |= AM_CHNL_EMPTY;
		}
	}
	mutex_exit(&chptr->ch_lock);

	/* Underflowed */
	if (empty == B_TRUE) {
		am_send_signal(chptr->ch_statep, stpptr);
	}

	/* EOF markers */
	for (; EOF_count; EOF_count--) {
		info->play.eof++;
		am_send_signal(chptr->ch_statep, stpptr);
	}

	ATRACE("am_get_samples() done_getting_samples", chptr);

	/* now we are done, so return how many samples we have */

	ATRACE_32("am_get_samples() normal return", ret_samples);

	/* make sure virtual channels are still active */
	if (mode == AM_MIXER_MODE && ad_infop->ad_codec_type == AM_TRAD_CODEC) {
		if (ret_samples) {
			if (info->play.active == 0) {
				active_signal = B_TRUE;
				info->play.active = 1;
			}
			hw_info->play.active = 1;
		}
		if (empty == B_TRUE) {
			if (info->play.active == 1) {
				active_signal = B_TRUE;
				info->play.active = 0;
			}
			/* we don't turn off the h/w active flag here */
		}
	}
	/* send the signals for active change */
	if (active_signal == B_TRUE) {
		am_send_signal(chptr->ch_statep, stpptr);
	}

	mutex_enter(&chptr->ch_lock);

	return (ret_samples);

}	/* am_get_samples() */

/*
 * am_play_shutdown_multi()
 *
 * Description:
 *	This routine is used to clean things up when the Audio Driver will
 *	no longer be servicing it's play interrupts. I.e., play interrupts
 *	have been turned off.
 *
 *	This routine makes sure that any DRAINs waiting for an interrupt are
 *	cleared.
 *
 *	It is also used to coordinate shutting down play so that we can
 *	switch between MIXER and COMPAT modes.
 *
 *	NOTE: We use the EOF_count to also determine if we have an active
 *		flag change and thus need a signal sent.
 *
 * Arguments:
 *	audiohdl_t	handle		Handle to the device
 *	int		channel		For multi-stream Codecs this is the
 *					stream to shutdown.
 *
 * Returns:
 *	void
 */
static void
am_play_shutdown_multi(audiohdl_t handle, int channel)
{
	audio_state_t			*statep = AUDIO_HDL2STATE(handle);
	audio_ch_t			*chptr;
	am_apm_private_t		*stpptr;
	am_ch_private_t			*chpptr;
	audio_info_t			*info;
	int				EOF_count = 0;

	ATRACE("in am_play_shutdown_multi()", handle);
	ASSERT(statep);

	chptr = &statep->as_channels[channel];
	stpptr = chptr->ch_apm_infop->apm_private;

	mutex_enter(&chptr->ch_lock);
	/*
	 * The channel may have been closed while we waited on the mutex.
	 * So once we get it we make sure the channel is still valid.
	 */
	chpptr = chptr->ch_private;
	if (!(chptr->ch_flags & AUDIO_CHNL_ALLOCATED) ||
	    chptr->ch_info.pid == 0 ||
	    (chpptr->acp_flags & AM_CHNL_OPEN) == 0) {
		ATRACE("am_play_shutdown_multi() channel closed", chptr);
		mutex_exit(&chptr->ch_lock);
		return;
	} else if (chpptr->acp_flags &
	    (AM_CHNL_DRAIN|AM_CHNL_DRAIN_NEXT_INT|AM_CHNL_EMPTY|\
	    AM_CHNL_ALMOST_EMPTY1|AM_CHNL_ALMOST_EMPTY2|AM_CHNL_CLOSING)) {
		/* clear a bunch of flags */
		chpptr->acp_flags &= ~(AM_CHNL_DRAIN|AM_CHNL_DRAIN_NEXT_INT|
		    AM_CHNL_ALMOST_EMPTY1|AM_CHNL_ALMOST_EMPTY2);

		/* are we empty? */
		if (audio_sup_get_audio_data_cnt(chptr) == 0) {
			/* yes, so mark as empty */
			chpptr->acp_flags |= AM_CHNL_EMPTY;
		}

		/* turn off the channel, but only if not paused */
		info = chptr->ch_info.info;
		if (!info->play.pause && info->play.active) {
			EOF_count++;
			info->play.active = 0;
		}

		am_audio_drained(chptr);

		/* make sure we send all pending signals */
		EOF_count += chpptr->acp_EOF[chpptr->acp_EOF_toggle];
		chpptr->acp_EOF[chpptr->acp_EOF_toggle] = 0;

		AUDIO_TOGGLE(chpptr->acp_EOF_toggle);

		EOF_count += chpptr->acp_EOF[chpptr->acp_EOF_toggle];
		chpptr->acp_EOF[chpptr->acp_EOF_toggle] = 0;

		mutex_exit(&chptr->ch_lock);

		for (; EOF_count; EOF_count--) {
			info->play.eof++;
			am_send_signal(statep, stpptr);
		}
	} else {
		/* we can free the lock now */
		mutex_exit(&chptr->ch_lock);
	}

	ATRACE("am_play_shutdown_multi() returning", statep);

	return;

}	/* am_play_shutdown_multi() */

/*
 * am_play_shutdown_trad()
 *
 * Description:
 *	This routine is used to clean things up when the Audio Driver will
 *	no longer be servicing it's play interrupts. I.e., play interrupts
 *	have been turned off.
 *
 *	This routine makes sure that any DRAINs waiting for an interrupt are
 *	cleared.
 *
 *	It is also used to coordinate shutting down play so that we can
 *	switch between MIXER and COMPAT modes.
 *
 * Arguments:
 *	audiohdl_t	handle		Handle to the device
 *	audio_apm_info_t *apm_infop	Pointer to APM info
 *
 * Returns:
 *	void
 */
static void
am_play_shutdown_trad(audiohdl_t handle, audio_apm_info_t *apm_infop)
{
	audio_state_t			*statep = AUDIO_HDL2STATE(handle);
	audio_ch_t			*chptr;
	am_ch_private_t			*chpptr;
	audio_info_t			*info;
	audio_info_t			*hw_info;
	am_apm_private_t		*stpptr;
	int				EOF_count;
	int				i;
	int				max_chs;

	ATRACE("in am_play_shutdown_trad()", handle);
	ASSERT(statep);

	max_chs = statep->as_max_chs;
	stpptr = apm_infop->apm_private;
	hw_info = apm_infop->apm_ad_state;

	mutex_enter(&apm_infop->apm_lock);
	if (stpptr->am_flags & AM_PRIV_SW_MODES) {
		mutex_exit(&apm_infop->apm_lock);

		ATRACE("am_play_shutdown_trad() change mode shutdown", stpptr);

		/* don't worry about signal, the mode switch will send one */
		hw_info->play.active = 0;

		/* let the mode change proceed */
		mutex_enter(&stpptr->am_mode_lock);
		cv_signal(&stpptr->am_mode_cv);
		mutex_exit(&stpptr->am_mode_lock);

		return;
	}
	mutex_exit(&apm_infop->apm_lock);

	/* go through all the channels */
	for (i = 0, chptr = &statep->as_channels[0];
	    i < max_chs; i++, chptr++) {
		/* skip non-AUDIO and unallocated channels */
		mutex_enter(&chptr->ch_lock);

		if (!(chptr->ch_flags & AUDIO_CHNL_ALLOCATED) ||
		    chptr->ch_info.dev_type != AUDIO ||
		    chptr->ch_info.pid == 0) {
			mutex_exit(&chptr->ch_lock);
			continue;
		}

		chpptr = chptr->ch_private;

		ATRACE_32("am_play_shutdown_trad() checking flags",
		    chpptr->acp_flags);

		info = chptr->ch_info.info;
		if (chpptr->acp_flags &
		    (AM_CHNL_DRAIN|AM_CHNL_DRAIN_NEXT_INT|\
		    AM_CHNL_EMPTY|AM_CHNL_ALMOST_EMPTY1|\
		    AM_CHNL_ALMOST_EMPTY2|AM_CHNL_CLOSING)) {
			/* clear a bunch of flags */
			chpptr->acp_flags &=
			    ~(AM_CHNL_DRAIN|AM_CHNL_DRAIN_NEXT_INT|\
			    AM_CHNL_ALMOST_EMPTY1|AM_CHNL_ALMOST_EMPTY2);

			/* are we empty? */
			if (audio_sup_get_audio_data_cnt(chptr) == 0) {
				/* yes, so mark as empty */
				chpptr->acp_flags |= AM_CHNL_EMPTY;
			}

			/* turn off the ch, but only if not paused */
			if (!info->play.pause) {
				info->play.active = 0;
			}

			ATRACE("am_play_shutdown_trad() regular drain", chptr);

			am_audio_drained(chptr);
		} else {
			/* turn off the ch, but only if not paused */
			if (!info->play.pause) {
				info->play.active = 0;
			}
		}

		/* make sure we send all pending signals */
		chpptr = chptr->ch_private;

		EOF_count = chpptr->acp_EOF[chpptr->acp_EOF_toggle];
		chpptr->acp_EOF[chpptr->acp_EOF_toggle] = 0;

		AUDIO_TOGGLE(chpptr->acp_EOF_toggle);

		EOF_count += chpptr->acp_EOF[chpptr->acp_EOF_toggle];
		chpptr->acp_EOF[chpptr->acp_EOF_toggle] = 0;

		mutex_exit(&chptr->ch_lock);

		for (; EOF_count; EOF_count--) {
			info->play.eof++;

			am_send_signal(statep, stpptr);
		}
	}

	/* turn off the hardware active flag, always send a signal */
	hw_info->play.active = 0;
	am_send_signal(statep, stpptr);

	ATRACE("am_play_shutdown_trad() returning", statep);

	return;

}	/* am_play_shutdown_trad() */

/*
 * am_release_ad_access()
 *
 * Description:
 *	This routine is used to release the serial access to the audio driver
 *	entry points.
 *
 * Arguments:
 *	am_apm_private_t *stpptr	Ptr to APM private data
 *
 * Returns:
 *	Void
 */
static void
am_release_ad_access(am_apm_private_t *stpptr)
{
	ATRACE("in am_release_ad_access()", stpptr);
	ATRACE("am_release_ad_access() curthread", curthread);

	/* wait for all other calls into the audio driver to return */
	mutex_enter(&stpptr->am_ad_lock);

	ASSERT(stpptr->am_ad_in & AM_APM_IN_DRIVER);

	/* we're done, so release any waiting threads */
	stpptr->am_ad_in &= ~AM_APM_IN_DRIVER;

	/* wake up one thread waiting on this CV */
	cv_signal(&stpptr->am_ad_cv);

	mutex_exit(&stpptr->am_ad_lock);

	ATRACE("am_release_ad_access() done", curthread);

}	/* am_release_ad_access() */

/*
 * am_set_record_streams()
 *
 * Description:
 *	Set the STREAMS high and low water marks for the record channel. We try
 *	this when the audio channel is initially opened. If that fails,
 *	am_send_audio_common() will also make an attempt to set the water marks.
 *	Otherwise, left alone the STREAMS default settings overflow almost
 *	immediately at the higher sample rates.
 *
 * Arguments:
 *      audio_ch_t	*chptr		Pointer to the channel structure
 *
 * Returns:
 *	AUDIO_SUCCESS		High and Low water marks increased
 *	AUDIO_FAILURE		High and Low water marks not increased
 */
int
am_set_record_streams(audio_ch_t *chptr)
{
	mblk_t			*mop;
	struct stroptions	*sop;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*sop));

	if (mop = allocb(sizeof (struct stroptions), BPRI_HI)) {
		mop->b_datap->db_type = M_SETOPTS;
		mop->b_wptr += sizeof (struct stroptions);
		sop = (struct stroptions *)mop->b_rptr;
		sop->so_flags = SO_HIWAT | SO_LOWAT;
		sop->so_hiwat = AM_MAX_QUEUED_MSGS_SIZE;
		sop->so_lowat = AM_MIN_QUEUED_MSGS_SIZE;

		am_safe_putnext(chptr, mop);

		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*sop));

		ATRACE("am_set_record_streams() adjustment successful", 0);

		return (AUDIO_SUCCESS);
	}

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*sop));

	ATRACE("am_set_record_streams() adjustment failed", 0);

	return (AUDIO_FAILURE);

}	/* am_set_record_streams() */

/*
 * am_send_audio_common()
 *	Common code between am_send_audio_multi() and am_send_audio_trad().
 *
 * Arguments:
 *	audio_ch_t	*chptr		Pointer to the channel structure
 *	void		*buf		The buffer to get audio from
 *	int		samples		The number of samples the Codec sent
 *
 * Returns:
 *	Void
 */
static void
am_send_audio_common(audio_ch_t *chptr, void *buf, int samples)
{
	audio_state_t		*statep = chptr->ch_statep;
	audio_info_t		*info = chptr->ch_info.info;
	am_ch_private_t		*chpptr = chptr->ch_private;
	mblk_t			*mp;
	queue_t			*q = RD(chptr->ch_qptr);
	size_t			size;
	int			bytes_per_samplef;
	int			channels = info->record.channels;
	int			mp_size;
	int			precision = info->record.precision;
	int			remaining;

	ATRACE("in am_send_audio_common()", chptr);

	ASSERT(statep);
	ASSERT(MUTEX_HELD(&chptr->ch_lock));

	/*
	 * Check if the STREAMS water marks for the record channel have been
	 * properly set. If not, try and set them here.
	 */
	if (!(chpptr->acp_flags & AM_CHNL_RSTREAMS_SET)) {
		ATRACE("am_send_audio_common() adjusting streams queue",
		    chpptr);
		if (am_set_record_streams(chptr) == AUDIO_SUCCESS) {
			ATRACE("am_send_audio_common() streams queue adjustment"
			    " successful", chpptr);
			chpptr->acp_flags |= AM_CHNL_RSTREAMS_SET;
		}
	}

	/* figure out how many bytes there are in a sample frame */
	bytes_per_samplef = channels * (precision >> AUDIO_PRECISION_SHIFT);
	ATRACE_32("am_send_audio_common() bytes_per_samplef",
	    bytes_per_samplef);

	/* figure out how many bytes we've got */
	size = samples * (precision >> AUDIO_PRECISION_SHIFT);
	ATRACE_32("am_send_audio_common() size", size);

	/* first we see if we have a partial buffer waiting to be sent */
	if (chpptr->acp_rec_mp) {	/* yup, we need to fill it first */
		ATRACE("am_send_audio_common() filling partial buffer",
		    chpptr->acp_rec_mp);

		mp = chpptr->acp_rec_mp;

		/*
		 * Figure out how much of the buffer is remaining. We don't
		 * use the record buffer size because it may have changed
		 * since the message was allocated.
		 */
		remaining = chpptr->acp_rec_remaining;
		ATRACE_32("am_send_audio_common() remaining", remaining);

		/* make sure we've got enough to fill this buffer */
		if (remaining > size) {
			/* we don't, so use what we have and return */
			bcopy(buf, mp->b_wptr, size);
			mp->b_wptr += size;
			chpptr->acp_rec_remaining -= size;
			info->record.samples += size / bytes_per_samplef;
			ATRACE("am_send_audio_common() not enough", mp);

			/* make sure the channel is still active */
			info->record.active = 1;

			return;
		}

		/* we do, so fill and then go on to get a new buffer */
		bcopy(buf, mp->b_wptr, remaining);
		mp->b_wptr += remaining;
		info->record.samples += remaining / bytes_per_samplef;
		ASSERT(q == RD(q));

		am_safe_putnext(chptr, mp);

		chpptr->acp_rec_mp = NULL;
		chpptr->acp_rec_remaining = 0;
		buf = (char *)buf + remaining;
		size -= remaining;
		ATRACE_32("am_send_audio_common() partial buffer filled", size);
		ASSERT(chpptr->acp_rec_remaining == 0);
	}
	ASSERT(chpptr->acp_rec_mp == NULL);

	/* start with a full buffer */
	remaining = info->record.buffer_size;

	/* now place remaining data into new buffers */
	while (size) {

		/* buffer_size may change during loop */
		mp_size = info->record.buffer_size;

		if ((mp = allocb(mp_size, BPRI_HI)) == NULL) {
			/*
			 * Often times when one allocb() fails we get many
			 * more that fail. We don't want this error message
			 * to spew uncontrolled. So we set this flag and the
			 * next time if it's set we don't display the message.
			 * Once we get a success we clear the flags, thus one
			 * message per continuous set of failures.
			 */
			if (!(chpptr->acp_flags & AM_CHNL_CLIMIT)) {
				audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
				    "mixer: send_audio_c() "
				    "allocb() failed, recorded audio lost");
				chpptr->acp_flags |= AM_CHNL_CLIMIT;
			}

			ATRACE("am_send_audio_common() allocb() failed",
				chptr);
			info->record.error = 1;
			return;
		}
		chpptr->acp_flags &= ~AM_CHNL_CLIMIT;

		mp->b_datap->db_type = M_DATA;

		if (mp_size > size) {
			/* partial buffer */
			bcopy(buf, mp->b_rptr, size);
			mp->b_wptr += size;
			chpptr->acp_rec_remaining = mp_size - size;
			info->record.samples += size / bytes_per_samplef;
			chpptr->acp_rec_mp = mp;
			ATRACE("am_send_audio_common() new not enough", mp);
			break;
		}
		/* full buffer */
		bcopy(buf, mp->b_rptr, mp_size);
		mp->b_wptr += mp_size;
		info->record.samples += mp_size / bytes_per_samplef;
		ASSERT(q == RD(q));

		am_safe_putnext(chptr, mp);

		ASSERT(chpptr->acp_rec_mp == NULL);
		chpptr->acp_rec_remaining = 0;
		buf = (char *)buf + mp_size;
		size -= mp_size;

		/* start with a full buffer for the next loop */
		remaining = info->record.buffer_size;
	}

	/* make sure the channel is still active */
	info->record.active = 1;

	ATRACE("am_send_audio_common() done", buf);

}	/* am_send_audio_common() */

/*
 * am_send_audio_multi()
 *
 * Description:
 *	This routine is used by multi-channel Codecs to send a single stream
 *	of audio data to an individual channel.
 *
 * Arguments:
 *	audio_state_t	*statep		Pointer to the device instance's state
 *	am_ad_info_t	*ad_infop	Ptr to the Audio Driver's config info
 *	void		*buf		The buffer to get audio from
 *	int		channel		The device channel number
 *	int		samples		The number of samples the Codec sent
 *
 *	NOTE: The variable "samples" is the number of samples the hardware
 *		sent. So it is samples at the hardware's sample rate.
 *
 * Returns:
 *	void
 */
/*ARGSUSED*/
static void
am_send_audio_multi(audio_state_t *statep, am_ad_info_t *ad_infop, void *buf,
	int channel, int samples)
{
	audio_ch_t		*chptr = &statep->as_channels[channel];
	audio_info_t		*info = chptr->ch_info.info;
	am_apm_private_t	*stpptr = chptr->ch_apm_infop->apm_private;
	am_ch_private_t		*chpptr = chptr->ch_private;
	size_t			size;
	size_t			size_plus_rb;
	int			channels = info->record.channels;

	ASSERT(statep);

	/* skip paused AUDIO channels */
	if (info->record.pause) {
		return;
	}

	/* make sure we can put the audio before we waste time converting it */
	switch (am_test_canputnext(chptr)) {
	case AM_CHNL_CLOSED:
		/* Channel closed on us */
		ATRACE("am_send_audio_multi() channel closed", chptr);
		return;
	case AUDIO_FAILURE:
		info->record.active = 0;
		info->record.error = 1;
		ATRACE_32("am_send_audio_multi() ch flow controlled",
		    chptr->ch_info.ch_number);
		return;
	case AUDIO_SUCCESS:
				/* FALLTHROUGH */
	default:
		break;
	}

	/* make sure the # of samples is modulo the # of H/W channels */
	if (channels != AUDIO_CHANNELS_MONO && (samples % channels) != 0) {
		ATRACE_32("am_send_audio_multi() bad sample size", samples);
		samples -= samples % channels;
	}

	mutex_enter(&chptr->ch_lock);

	/* make sure the conversion buffer is large enough */
	size = samples << AM_TIMES_8_SHIFT;
	size_plus_rb = size + chpptr->acp_ch_rbuf_size;
	if (am_update_conv_buffer(chptr, size_plus_rb, AUDIO_RECORD) ==
		AUDIO_FAILURE) {
		mutex_exit(&chptr->ch_lock);
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
		    "!mixer: send_audio_multi() couldn't allocate "
		    "conversion buffer, audio lost");
		return;
	}

	/* convert to canonical format */
	am_convert_to_int(buf, chpptr->acp_ch_rconv1, samples,
	    info->record.precision, info->record.encoding, stpptr->am_rflags);

	/* send to the application */
	am_send_audio_common(chptr, chpptr->acp_ch_rconv1, samples);

	mutex_exit(&chptr->ch_lock);

	ATRACE("am_send_audio_multi() done", buf);

}	/* am_send_audio_multi() */

/*
 * am_send_audio_trad_compat()
 *
 * Description:
 *	This routine is used by traditional Codecs to send a single recorded
 *	audio stream up to applications in COMPAT mode. The data is converted
 *	to the applications format, except the sample rate, which the hardware
 *	must match.
 *
 *	CAUTION: This routine is called from interrupt context, so memory
 *		allocation cannot sleep.
 *
 * Arguments:
 *	audio_state_t		*statep		Ptr to the dev instance's state
 *	audio_apm_info_t	*apm_infop	Personality module data struct
 *	int			*buf		The buffer to get audio from
 *	int			samples		The # of samples the Codec sent
 *
 * Returns:
 *	void
 */
static void
am_send_audio_trad_compat(audio_state_t *statep, audio_apm_info_t *apm_infop,
	int *buf, int samples)
{
	audio_ch_t		*chptr;
	am_ch_private_t		*chpptr;
	audio_info_t		*info;
	audio_info_t		*hw_info = apm_infop->apm_ad_state;
	am_apm_private_t	*stpptr = apm_infop->apm_private;
	size_t			size;
	size_t			size_plus_rb;
	uint_t			channels;
	uint_t			hw_channels;
	int			already_active;
	int			i;
	int			max_chs;

	ATRACE("in am_send_audio_trad_compat()", statep);
	ASSERT(statep);

	/* get the number of chs for this instance */
	max_chs = statep->as_max_chs;

	/* go through the chs looking for the only recording AUDIO ch */
	for (i = 0, chptr = &statep->as_channels[0]; i < max_chs;
	    i++, chptr++) {

		/* lock the channel before we check it out */
		mutex_enter(&chptr->ch_lock);

		/* skip non-AUDIO and unallocated channels */
		if (!(chptr->ch_flags & AUDIO_CHNL_ALLOCATED) ||
		    chptr->ch_info.dev_type != AUDIO ||
		    chptr->ch_info.pid == 0) {

			mutex_exit(&chptr->ch_lock);
			continue;
		}

		/* make sure this channel is valid */
		chpptr = chptr->ch_private;
		info = chptr->ch_info.info;
		if (chpptr == NULL || info == NULL ||
		    (chpptr->acp_flags & AM_CHNL_OPEN) == 0) {
			mutex_exit(&chptr->ch_lock);
			ATRACE("am_get_audio_trad_compat() channel closed",
			    chptr);
			continue;
		}

		/* make sure this channel is reading */
		if (!chpptr->acp_reading) {
			ATRACE("am_send_audio_trad_compat() not recording",
			    chpptr);
			mutex_exit(&chptr->ch_lock);
			continue;
		}

		/* skip paused AUDIO channels */
		if (info->record.pause) {
			mutex_exit(&chptr->ch_lock);
			return;
		}

		mutex_exit(&chptr->ch_lock);

		ATRACE_32("am_send_audio_trad_compat() found channel", i);
		break;
	}
	if (i >= max_chs) {
		ATRACE("am_send_audio_trad_compat() done, no rec channel", buf);
		return;
	}

	/* make sure we can put the audio before we waste time converting it */
	switch (am_test_canputnext(chptr)) {
	case AM_CHNL_CLOSED:
		/* Channel closed on us */
		ATRACE("am_send_audio_trad_compat() channel closed", chptr);
		return;
	case AUDIO_FAILURE:
		am_send_signal(statep, stpptr);
		info->record.active = 0;
		info->record.error = 1;
		ATRACE_32("am_send_audio_trad_compat() ch flow controlled",
		    chptr->ch_info.ch_number);
		return;
	case AUDIO_SUCCESS:
				/* FALLTHROUGH */
	default:
		break;
	}

	mutex_enter(&chptr->ch_lock);

	/*
	 * We had to free the lock above to make warlock happy. Unfortunately
	 * it's possible that the channel closed between releasing and
	 * reacquiring the lock. So we have to check again.
	 */
	if (!(chptr->ch_flags & AUDIO_CHNL_ALLOCATED) ||
	    chptr->ch_info.dev_type != AUDIO || chptr->ch_info.pid == 0) {
		mutex_exit(&chptr->ch_lock);
		ATRACE("am_send_audio_trad_compat() ch closed on us", chptr);
		return;
	}

	hw_channels = stpptr->am_hw_rchs;
	channels = info->record.channels;

	size = (samples + AM_EXTRA_SAMPLES) << AM_TIMES_8_SHIFT;
	size_plus_rb = size + chpptr->acp_ch_rbuf_size;

	if (am_update_conv_buffer(chptr, size_plus_rb, AUDIO_RECORD) ==
		AUDIO_FAILURE) {
		mutex_exit(&chptr->ch_lock);
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
		    "!mixer: send_audio_trad(C) couldn't allocate "
		    "conversion buffer, audio lost");
		return;
	}

	/* convert between mono <---> stereo */
	am_convert_int_mono_stereo(buf, chpptr->acp_ch_rconv1, &samples,
	    hw_channels, channels);

	/* now convert to the application's format */
	am_convert_to_format(chpptr->acp_ch_rconv1, chpptr->acp_ch_rconv2,
	    samples, info->record.precision, info->record.encoding, 0);

	/* update recorded sample count */
	hw_info->record.samples += samples / hw_channels;

	/* send to the application */
	already_active = info->record.active;
	am_send_audio_common(chptr, chpptr->acp_ch_rconv2, samples);

	mutex_exit(&chptr->ch_lock);

	if (already_active != info->record.active) {
		am_send_signal(statep, stpptr);
	}

	ATRACE("am_send_audio_trad_compat() done", buf);

}	/* am_send_audio_trad_compat() */

/*
 * am_send_audio_trad_mixer()
 *
 * Description:
 *	This routine is used by traditional Codecs to send multiple recorded
 *	audio stream up to applications in MIXER mode. The data is converted
 *	to the applications format, including sample rate.
 *
 *	CAUTION: This routine is called from interrupt context, so memory
 *		allocation cannot sleep.
 *
 * Arguments:
 *	audio_state_t		*statep		Ptr to the dev instance's state
 *	audio_apm_info_t	*apm_infop	Personality module data struct
 *	int			*buf		The buffer to get audio from
 *	int			samples		The # of samples the Codec sent
 *
 * Returns:
 *	void
 */
static void
am_send_audio_trad_mixer(audio_state_t *statep, audio_apm_info_t *apm_infop,
	int *buf, const int samples)
{
	audio_ch_t		*chptr;
	am_ch_private_t		*chpptr;
	audio_info_t		*info;
	audio_info_t		*hw_info = apm_infop->apm_ad_state;
	am_ad_info_t		*ad_infop = apm_infop->apm_ad_infop;
	am_apm_private_t	*stpptr = apm_infop->apm_private;
	am_ad_src_entry_t	*rsrs = ad_infop->ad_record.ad_conv;
	int			*conv_data;
	size_t			size;
	size_t			size_plus_rb;
	uint_t			channels;
	uint_t			hw_channels;
	int			already_active;
	int			i;
	int			max_chs;
	int			tmp_samples;

	ATRACE("in am_send_audio_trad_mixer()", statep);
	ASSERT(statep);

	/* get the number of chs for this instance */
	max_chs = statep->as_max_chs;

	hw_channels = stpptr->am_hw_rchs;
	ATRACE_32("am_send_audio_trad_mixer() am_in_chs", stpptr->am_in_chs);

	/* go through the chs looking for each AUDIO ch */
	for (i = 0, chptr = &statep->as_channels[0];
	    i < max_chs; i++, chptr++) {

		/* lock the channel before we check it out */
		mutex_enter(&chptr->ch_lock);

		/* skip non-AUDIO and unallocated channels */
		if (!(chptr->ch_flags & AUDIO_CHNL_ALLOCATED) ||
		    chptr->ch_info.dev_type != AUDIO ||
		    chptr->ch_info.pid == 0) {

			mutex_exit(&chptr->ch_lock);
			continue;
		}

		/* make sure this channel is valid */
		chpptr = chptr->ch_private;
		info = chptr->ch_info.info;
		if (chpptr == NULL || info == NULL ||
		    (chpptr->acp_flags & AM_CHNL_OPEN) == 0) {
			mutex_exit(&chptr->ch_lock);
			ATRACE("am_get_audio_trad_mixer() channel closed",
			    chptr);
			continue;
		}

		/* make sure this channel is reading */
		if (!chpptr->acp_reading) {
			ATRACE("am_send_audio_trad_mixer() not recording",
			    chpptr);
			mutex_exit(&chptr->ch_lock);
			continue;
		}

		/* skip paused AUDIO channels */
		if (info->record.pause) {
			mutex_exit(&chptr->ch_lock);
			continue;
		}

		/* make sure we can put the audio before we waste time */
		mutex_exit(&chptr->ch_lock);

		switch (am_test_canputnext(chptr)) {
		case AM_CHNL_CLOSED:
			/* Channel closed on us */
			ATRACE("am_send_audio_trad_mixer() channel closed",
			    chptr);
			return;
		case AUDIO_FAILURE:
			am_send_signal(statep, stpptr);
			info->record.active = 0;
			info->record.error = 1;
				ATRACE_32(
				    "am_send_audio_trad_mixer() ch flow "
				    "controlled", chptr->ch_info.ch_number);
			continue;
		case AUDIO_SUCCESS:
					/* FALLTHROUGH */
		default:
			break;
		}
		mutex_enter(&chptr->ch_lock);

		ATRACE_32("am_send_audio_trad_mixer() found channel", i);

		/* don't let samples get modified */
		tmp_samples = samples;

		channels = info->record.channels;

		/* use the mode lock to keep the mode from switching */
		mutex_enter(&stpptr->am_mode_lock);

		/*
		 * Make sure there's enough memory to convert to int. We
		 * ask for more so that after SRC we hopefully don't need
		 * to free and allocate again. We also need to make sure
		 * we've got enough to go from mono to stereo.
		 */
		size = (tmp_samples + AM_EXTRA_SAMPLES) << AM_TIMES_8_SHIFT;
		size_plus_rb = size + chpptr->acp_ch_rbuf_size;

		if (am_update_conv_buffer(chptr, size_plus_rb, AUDIO_RECORD) ==
		    AUDIO_FAILURE) {
			mutex_exit(&stpptr->am_mode_lock);
			mutex_exit(&chptr->ch_lock);
			audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
			    "!mixer: send_audio_trad(C) couldn't "
			    "allocate conversion buffer, audio lost");
			return;
		}

		/* convert between mono <---> stereo */
		am_convert_int_mono_stereo(buf,
			(int *)((char *)chpptr->acp_ch_rconv1 +
			chpptr->acp_ch_rbuf_size), &tmp_samples, hw_channels,
			channels);

		/*
		 * Make sure we have the buffers to perform sample rate
		 * conversion, then do the sample rate conversion.
		 */
		if (am_update_src_buffer(chptr, samples, hw_channels,
		    AUDIO_RECORD) == AUDIO_FAILURE) {
			mutex_exit(&stpptr->am_mode_lock);
			mutex_exit(&chptr->ch_lock);
			audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
			    "!mixer: send_audio_trad(M) couldn't "
			    "allocate src buffer, audio lost");
			continue;
		}

		conv_data = rsrs->ad_src_convert(AM_SRC_CHPTR2HDL(chptr),
		    info->record.channels, AUDIO_RECORD, chpptr->acp_ch_rconv1,
		    chpptr->acp_ch_rsrc1, chpptr->acp_ch_rsrc2, &tmp_samples);

		ASSERT(tmp_samples <= (chpptr->acp_ch_rsrc_siz >>
			AM_TIMES_4_SHIFT));

		if (!conv_data) {
			mutex_exit(&stpptr->am_mode_lock);
			mutex_exit(&chptr->ch_lock);
			audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
			    "!mixer: send_audio_trad(M) sample "
			    "rate conversion failed, audio lost");
			continue;
		}

		/*
		 * Make sure there's enough memory to convert to format.
		 * We also need to make sure we've got enough to go from
		 * mono to stereo
		 */
		size = tmp_samples << AM_TIMES_8_SHIFT;
		size_plus_rb = size + chpptr->acp_ch_rbuf_size;
		if (am_update_conv_buffer(chptr, size_plus_rb, AUDIO_RECORD) ==
		    AUDIO_FAILURE) {
			mutex_exit(&stpptr->am_mode_lock);
			mutex_exit(&chptr->ch_lock);
			audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
			    "!mixer: send_audio_trad(C) couldn't "
			    "allocate conversion buffer, audio lost");
			return;
		}

		/* apply gain to the sample rate converted audio */
		am_apply_gain_balance(conv_data, tmp_samples, channels,
		    info->record.gain, info->record.balance);

		/* now convert to the application's format */
		am_convert_to_format(conv_data, chpptr->acp_ch_rconv2,
		    tmp_samples, info->record.precision, info->record.encoding,
		    0);

		mutex_exit(&stpptr->am_mode_lock);

		/* send to the application */
		already_active = info->record.active;
		am_send_audio_common(chptr, chpptr->acp_ch_rconv2, tmp_samples);

		ATRACE("am_send_audio_trad_mixer() done with channel", chptr);

		mutex_exit(&chptr->ch_lock);

		if (already_active != info->record.active) {
			am_send_signal(statep, stpptr);
		}

	}

	/* update recorded sample count */
	hw_info->record.samples += samples / hw_channels;

	ATRACE("am_send_audio_trad_mixer() done", buf);

}	/* am_send_audio_trad_mixer() */

/*
 * am_serialize_ad_access()
 *
 * Description:
 *	This routine is used to guarantee that all of the calls into the
 *	audio driver, except for ad_ioctl() and ad_iocdata(), are serialized.
 *
 * Arguments:
 *	am_apm_private_t *stpptr	Ptr to APM private data
 *
 * Returns:
 *	Void
 */
static void
am_serialize_ad_access(am_apm_private_t *stpptr)
{
	ATRACE("in am_serialize_ad_access()", stpptr);
	ATRACE("am_serialize_ad_access() curthread", curthread);

	/* wait for all other calls into the audio driver to return */
	mutex_enter(&stpptr->am_ad_lock);

	while (stpptr->am_ad_in & (AM_APM_IN_DRIVER|AM_APM_FREEZE)) {
		ATRACE("am_serialize_ad_access() in cv_wait()", curthread);
		cv_wait(&stpptr->am_ad_cv, &stpptr->am_ad_lock);
		ATRACE("am_serialize_ad_access() cv_wait() returned",
		    curthread);
	}

	ASSERT(!(stpptr->am_ad_in & AM_APM_IN_DRIVER));

	/* we have permission to enter, so flag as busy */
	stpptr->am_ad_in |= AM_APM_IN_DRIVER;

	mutex_exit(&stpptr->am_ad_lock);

	ATRACE("am_serialize_ad_access() done", curthread);

}	/* am_serialize_ad_access() */

/*
 * Task queue callbacks.
 */

/*
 * am_hw_task()
 *
 * Description:
 *	Called by the task queue to update the hardware state based on
 *	input from the audio driver. This is usually driven by the user
 *	pressing a button, like volume up/down, on the audio device.
 *
 *	NOTE: There isn't an input mute like there is an output mute, so we
 *		set the input gain to 0 and save the old gain for unmute. If
 *		another app raised the input gain then the input gain isn't
 *		0 and thus we are no longer muted.
 *
 * Arguments:
 *	void		*arg	Argument structure
 *
 * Returns:
 *	void
 */
static void
am_hw_task(void *arg)
{
	audio_state_t		*statep =
				    ((am_state_ch_args_t *)arg)->asca_statep;
	audio_apm_info_t	*apm_infop =
				    ((am_state_ch_args_t *)arg)->asca_apm_infop;
	audio_info_t		*hw_info =
				    (audio_info_t *)apm_infop->apm_ad_state;
	am_ad_info_t		*ad_infop;
	am_apm_private_t	*stpptr = apm_infop->apm_private;
	int			cmd = ((am_state_ch_args_t *)arg)->asca_cmd;
	int			dir = ((am_state_ch_args_t *)arg)->asca_dir;
	int			value = ((am_state_ch_args_t *)arg)->asca_value;
	int			balance;
	int			gain;
	int			send_signal = 0;
	uint_t			channels;

	ATRACE("in am_hw_task() statep", statep);
	ATRACE_32("am_hw_task() cmd", cmd);
	ATRACE_32("am_hw_task() dir", dir);
	ATRACE_32("am_hw_task() value", value);
	ASSERT(statep);

	switch (cmd) {
	case AM_HWSC_SET_GAIN_ABS:
		gain = (int)((dir == AUDIO_PLAY) ?
		    hw_info->play.gain : hw_info->record.gain);
		balance = (int)((dir == AUDIO_PLAY) ?
		    hw_info->play.balance : hw_info->record.balance);
		channels = (dir == AUDIO_PLAY) ?
		    stpptr->am_hw_pchs : stpptr->am_hw_rchs;

		/*
		 * Check limits, jump out if we are already at the max or min
		 * value
		 */
		if (gain >= AUDIO_MAX_GAIN) {
			ATRACE_32("am_hw_task() ABS gain already at max", gain);
			break;
		} else if (gain <= AUDIO_MIN_GAIN) {
			ATRACE_32("am_hw_task() ABS gain already at min", gain);
			break;
		}

		/* apply the new absolute gain */
		gain = value;

		/* make sure the result isn't too big or small */
		if (gain > AUDIO_MAX_GAIN) {
			gain = AUDIO_MAX_GAIN;
		} else if (gain < AUDIO_MIN_GAIN) {
			gain = AUDIO_MIN_GAIN;
		}
		ATRACE_32("am_hw_task() new absolute gain", gain);

		if (am_set_gain(statep, apm_infop, channels, (uint_t)gain,
		    (uint_t)balance, dir, AM_SET_CONFIG_BOARD, AM_NO_FORCE,
		    AM_SERIALIZE) == AUDIO_SUCCESS) {
			if (dir == AUDIO_PLAY) {
				hw_info->play.gain = gain;
			} else {
				hw_info->record.gain = gain;
			}
		}

		send_signal++;

		break;
	case AM_HWSC_SET_BAL_ABS:
		gain = (int)((dir == AUDIO_PLAY) ?
		    hw_info->play.gain : hw_info->record.gain);
		balance = (int)((dir == AUDIO_PLAY) ?
		    hw_info->play.balance : hw_info->record.balance);
		channels = (dir == AUDIO_PLAY) ?
		    stpptr->am_hw_pchs : stpptr->am_hw_rchs;

		/*
		 * Check limits, jump out if we are already at the max or min
		 * value
		 */
		if (balance >= AUDIO_RIGHT_BALANCE) {
			ATRACE_32("am_hw_task() ABS balance"
			    " already right", balance);
			break;
		} else if (balance <= AUDIO_LEFT_BALANCE) {
			ATRACE_32("am_hw_task() ABS balance"
			    " already left", balance);
			break;
		}

		/* apply the new absolute balance */
		balance = value;

		/* make sure the result isn't too big or small */
		if (balance > AUDIO_RIGHT_BALANCE) {
			balance = AUDIO_RIGHT_BALANCE;
		} else if (balance < AUDIO_LEFT_BALANCE) {
			balance = AUDIO_LEFT_BALANCE;
		}
		ATRACE_32("am_hw_task() new absolute balance", balance);

		if (am_set_gain(statep, apm_infop, channels, (uint_t)gain,
		    (uint_t)balance, dir, AM_SET_CONFIG_BOARD, AM_NO_FORCE,
		    AM_SERIALIZE) == AUDIO_SUCCESS) {
			if (dir == AUDIO_PLAY) {
				hw_info->play.balance = (uchar_t)balance;
			} else {
				hw_info->record.balance = (uchar_t)balance;
			}
		}

		send_signal++;

		break;
	case AM_HWSC_SET_GAIN_DELTA:
		gain = (int)((dir == AUDIO_PLAY) ?
		    hw_info->play.gain : hw_info->record.gain);
		balance = (int)((dir == AUDIO_PLAY) ?
		    hw_info->play.balance : hw_info->record.balance);
		channels = (dir == AUDIO_PLAY) ?
		    stpptr->am_hw_pchs : stpptr->am_hw_rchs;

		/*
		 * Check limits, jump out if we are already at the max or min
		 * value
		 */
		if (value > 0 && gain >= AUDIO_MAX_GAIN) {
			ATRACE_32("am_hw_task() gain already at max", gain);
			break;
		} else if (value < 0 && gain <= AUDIO_MIN_GAIN) {
			ATRACE_32("am_hw_task() gain already at min", gain);
			break;
		}

		/* apply delta */
		gain += value;

		/* make sure the result isn't too big or small */
		if (gain > AUDIO_MAX_GAIN) {
			gain = AUDIO_MAX_GAIN;
		} else if (gain < AUDIO_MIN_GAIN) {
			gain = AUDIO_MIN_GAIN;
		}

		if (am_set_gain(statep, apm_infop, channels, (uint_t)gain,
		    (uint_t)balance, dir, AM_SET_CONFIG_BOARD, AM_NO_FORCE,
		    AM_SERIALIZE) == AUDIO_SUCCESS) {
			if (dir == AUDIO_PLAY) {
				hw_info->play.gain = gain;
			} else {
				hw_info->record.gain = gain;
			}
		}

		send_signal++;

		break;
	case AM_HWSC_SET_BAL_DELTA:
		gain = (int)((dir == AUDIO_PLAY) ?
		    hw_info->play.gain : hw_info->record.gain);
		balance = (int)((dir == AUDIO_PLAY) ?
		    hw_info->play.balance : hw_info->record.balance);
		channels = (dir == AUDIO_PLAY) ?
		    stpptr->am_hw_pchs : stpptr->am_hw_rchs;

		/*
		 * Check limits, jump out if we are already at the max or min
		 * value
		 */
		if (value > 0 && balance >= AUDIO_RIGHT_BALANCE) {
			ATRACE_32("am_hw_task() bal. already right", balance);
			break;
		} else if (value < 0 && balance <= AUDIO_LEFT_BALANCE) {
			ATRACE_32("am_hw_task() bal. already left", balance);
			break;
		}

		/* apply delta */
		balance += value;

		/* make sure the result isn't too big or small */
		if (balance > AUDIO_RIGHT_BALANCE) {
			balance = AUDIO_RIGHT_BALANCE;
		} else if (balance < AUDIO_LEFT_BALANCE) {
			balance = AUDIO_LEFT_BALANCE;
		}

		if (am_set_gain(statep, apm_infop, channels, (uint_t)gain,
		    (uint_t)balance, dir, AM_SET_CONFIG_BOARD, AM_NO_FORCE,
		    AM_SERIALIZE) == AUDIO_SUCCESS) {
			if (dir == AUDIO_PLAY) {
				hw_info->play.balance = (uchar_t)balance;
			} else {
				hw_info->record.balance = (uchar_t)balance;
			}
		}

		send_signal++;

		break;
	case AM_HWSC_MUTE_TOGGLE:
		if (dir == AUDIO_PLAY) {
			/* toggle mute */
			if (hw_info->output_muted) {
				value = AM_NOT_MUTED;
			} else {
				value = AM_MUTED;
			}

			/* set new mute */
			ad_infop = apm_infop->apm_ad_infop;
			if (am_ad_set_config(statep, stpptr, ad_infop,
			    AM_SET_CONFIG_BOARD, AM_OUTPUT_MUTE, AUDIO_PLAY,
			    value, NULL, AM_SERIALIZE) == AUDIO_SUCCESS) {
				hw_info->output_muted = (uchar_t)value;
			}
		} else {
			if (hw_info->record.gain) {
				stpptr->am_save_hw_rgain = hw_info->record.gain;
				value = AUDIO_MIN_GAIN;
			} else {
				value = stpptr->am_save_hw_rgain;
			}

			if (am_set_gain(statep, apm_infop,
			    stpptr->am_hw_rchs, (uint_t)value,
			    hw_info->record.balance, AUDIO_RECORD,
			    AM_SET_CONFIG_BOARD, AM_NO_FORCE, AM_SERIALIZE) ==
			    AUDIO_SUCCESS) {
				hw_info->record.gain = value;
			}
		}

		send_signal++;

		break;
	default:
		ATRACE_32("am_hw_task() unrecognized command", cmd);
		break;
	}

	/* free the argument memory */

	kmem_free(arg, sizeof (am_state_ch_args_t));

	if (send_signal) {
		am_send_signal(statep, stpptr);
	}

	ATRACE("am_hw_task() done", statep);

}	/* am_hw_task() */
