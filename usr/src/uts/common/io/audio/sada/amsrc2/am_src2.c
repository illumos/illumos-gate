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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Audio Mixer Sample Rate Conversion Routine 2
 *
 * This module is used by the audio mixer to perform sample rate conversion
 * of audio streams. The audio driver actually specifies which sample rate
 * conversion routine it wants to use, and then passes that information to
 * the audio mixer.
 *
 *	NOTE: This module depends on the misc/audiosup and misc/mixer
 *		modules being loaded 1st.
 *
 *	NOTE: We do NOT allocate the buffers used for sample rate conversion.
 *		That is the job of the audio mixer.
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/note.h>
#include <sys/audio.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/audio/audio_support.h>
#include <sys/audio/audio_src.h>
#include <sys/audio/audio_trace.h>
#include <sys/audio/am_src2.h>
#include <sys/audio/impl/am_src2_impl.h>
#include <sys/audio/impl/am_src2_table.h>

/*
 * Local sample rate conversion routines.
 */
static int am_src2_adjust(srchdl_t, int, int);
static int *am_src2_convert(srchdl_t, int, int, int *, int *, int *, int *);
static void am_src2_exit(srchdl_t, int);
static size_t am_src2_init(srchdl_t, int);
static size_t am_src2_size(srchdl_t, audio_prinfo_t *, int, int, int);
static int am_src2_update(srchdl_t, audio_prinfo_t *, audio_prinfo_t *,
	void *, int);
static int am_src2_up_s(am_src2_data_t *, int *, int *, int);
static int am_src2_up_m(am_src2_data_t *, int *, int *, int);
static int am_src2_dn_s(am_src2_data_t *, int *, int *, int);
static int am_src2_dn_m(am_src2_data_t *, int *, int *, int);

/*
 * Global variable to provide generic sample rate conversion facility.
 */
am_ad_src_entry_t am_src2 = {
	AM_SRC_VERSION,
	am_src2_init,
	am_src2_exit,
	am_src2_update,
	am_src2_adjust,
	am_src2_convert,
	am_src2_size
};

/*
 * Module Linkage Structures
 */
/* Linkage structure for loadable drivers */
static struct modlmisc amsrc2_modlmisc = {
	&mod_miscops,			/* drv_modops */
	AM_SRC2_MOD_NAME,		/* drv_linkinfo */
};

static struct modlinkage amsrc2_modlinkage =
{
	MODREV_1,			/* ml_rev */
	(void*)&amsrc2_modlmisc,	/* ml_linkage */
	NULL				/* NULL terminates the list */
};

/*
 *  Loadable Module Configuration Entry Points
 *
 *
 * _init()
 *
 * Description:
 *	Driver initialization, called when driver is first loaded.
 *
 * Arguments:
 *	None
 *
 * Returns:
 *	mod_install() status, see mod_install(9f)
 */
int
_init(void)
{
	int	error;

	ATRACE("in amsrc2 _init()", 0);

	/* Standard linkage call */
	if ((error = mod_install(&amsrc2_modlinkage)) != 0) {
		ATRACE_32("amsrc2 _init() error 1", error);
		return (error);
	}

	ATRACE("amsrc2 _init() successful", 0);

	return (error);

}	/* _init() */

/*
 * _fini()
 *
 * Description
 *	Module de-initialization, called when driver is to be unloaded.
 *
 * Arguments:
 *	None
 *
 * Returns:
 *	mod_remove() status, see mod_remove(9f)
 */
int
_fini(void)
{
	int	error;

	ATRACE("in amsrc2 _fini()", 0);

	if ((error = mod_remove(&amsrc2_modlinkage)) != 0) {
		ATRACE_32("amsrc2 _fini() mod_remove failed", error);
		return (error);
	}

	ATRACE_32("amsrc2 _fini() successful", error);

	return (error);

}	/* _fini() */

/*
 * _info()
 *
 * Description:
 *	Module information, returns information about the driver.
 *
 * Arguments:
 *	modinfo	*modinfop	Pointer to an opaque modinfo structure
 *
 * Returns:
 *	mod_info() status, see mod_info(9f)
 */
int
_info(struct modinfo *modinfop)
{
	int		rc;

	rc = mod_info(&amsrc2_modlinkage, modinfop);

	ATRACE_32("amsrc2 _info() returning", rc);

	return (rc);

}	/* _info() */

/*
 * am_src2_adjust()
 *
 * Description:
 *	This routine is used to adjust the number of hardware samples so we
 *	know how many channel samples were converted.
 *
 * Arguments:
 *	srchdl_t	handle		Mixer/src handle
 *	int		dir		Direction, AUDIO_PLAY or AUDIO_RECORD
 *	int		samples		The number of hardware samples
 *
 * Returns:
 *	>= 0				The number of channel samples
 *	AUDIO_FAILURE			Couldn't adjust the size
 */
static int
am_src2_adjust(srchdl_t	handle, int dir, int samples)
{
	am_src2_data_t		*pptr;
	int			value;

	ATRACE("in am_src2_adjust()", handle);
	ATRACE_32("am_src2_adjust() direction", dir);
	ATRACE_32("am_src2_adjust() samples", samples);

	/* Get the conversion info */
	if ((pptr = (am_src2_data_t *)am_get_src_data(handle, dir)) == NULL) {
		cmn_err(CE_WARN, "!amsrc2: src2_adjust() no pptr");
		return (AUDIO_FAILURE);
	}

	/* Do the math */
	mutex_enter(&pptr->src2_lock);
	ATRACE_32("am_src2_adjust() inFs", pptr->src2_inFs);
	ATRACE_32("am_src2_adjust() outFS", pptr->src2_outFs);
	value = (samples * pptr->src2_inFs) / pptr->src2_outFs;
	mutex_exit(&pptr->src2_lock);

	ATRACE_32("am_src2_adjust() returning", value);

	return (value);

}       /* am_src2_adjust() */

/*
 * am_src2_convert()
 *
 * Description:
 *	This routine manages the sample rate conversion process. It converts
 *	from src2_inFs to src2_outFs. The input stream must be 16-bit Linear
 *	PCM held as 32-bit integers.
 *
 *	The returned pointer, if valid, must be one of the two passed in
 *	pointers. Otherwise memory will become lost.
 *
 * Arguments:
 *	srchdl_t	handle		Mixer/src handle
 *	int		channels	The number of channels in conversion
 *	int		dir		Direction, AUDIO_PLAY or AUDIO_RECORD
 *	int		*src		Original data to convert
 *	int		*ptr1		Conversion buffer
 *	int		*ptr2		Conversion buffer (not used)
 *	int		*samples	Pointer to the number of samples to
 *					convert, and when we return, the number
 *					of samples converted.
 *
 * Returns:
 *	valid pointer			Pointer to the converted audio stream
 *	NULL				Conversion failed
 */
/*ARGSUSED*/
static int *
am_src2_convert(srchdl_t handle, int channels, int dir, int *src,
    int *ptr1, int *ptr2, int *samples)
{
	am_src2_data_t		*pdata;
	int			converted;

	ATRACE("in am_src2_convert()", handle);
	ATRACE_32("am_src2_convert() direction", dir);
	ATRACE_32("am_src2_convert() channels", channels);

	/* Get the sample rate conversion data */
	if ((pdata = (am_src2_data_t *)am_get_src_data(handle, dir)) == NULL) {
		cmn_err(CE_WARN, "!amsrc2: src2_convert() no pdata");
		return (NULL);
	}

	mutex_enter(&pdata->src2_lock);

	/* Set conversion function depending on direction and channels */
	if (dir == AUDIO_PLAY) {
		if (channels == AUDIO_CHANNELS_MONO) {
			pdata->src2_resample = am_src2_up_m;
		} else {
			ASSERT(channels == AUDIO_CHANNELS_STEREO);
			pdata->src2_resample = am_src2_up_s;
		}
	} else {
		ASSERT(dir == AUDIO_RECORD);
		if (channels == AUDIO_CHANNELS_MONO) {
			pdata->src2_resample = am_src2_dn_m;
		} else {
			ASSERT(channels == AUDIO_CHANNELS_STEREO);
			pdata->src2_resample = am_src2_dn_s;
		}

	}

	/* Resample */
	converted = pdata->src2_resample(pdata, src, ptr1, *samples);

	ATRACE_32("am_src2_convert() final number converted", converted);
	ATRACE("am_src2_convert() final conversions returning", ptr1);

	*samples = converted;

	mutex_exit(&pdata->src2_lock);

	return (ptr1);

}	/* am_src2_convert() */

/*
 * am_src2_exit()
 *
 * Description:
 *	Free the private data structure allocated in am_src2_init()
 *
 *	NOTE: We do NOT free the buffers used for sample rate conversion.
 *
 * Arguments:
 *	srchdl_t	handle		Mixer/src handle
 *	int		dir		Direction, AUDIO_PLAY or AUDIO_RECORD
 *
 * Returns:
 *	void
 */
static void
am_src2_exit(srchdl_t handle, int dir)
{
	am_src2_data_t		*pdata;

	ATRACE_32("am_src2_exit() direction", dir);

	/* Get pointers, based on which direction we are going */
	pdata = (am_src2_data_t *)am_get_src_data(handle, dir);

	ATRACE("am_src2_exit() data", pdata);

	if (pdata == NULL) {
		ATRACE("am_src2_exit() done", pdata);
		return;
	}

	/* Get the mutex */
	mutex_enter(&pdata->src2_lock);

	/* Free memory for table pointers */
	if (dir == AUDIO_PLAY) {
		kmem_free((void *)pdata->src2_tables,
			sizeof (*pdata->src2_tables) * (AM_SRC2_CPZC + 1));
	}

	/* Release and destroy the mutex */
	mutex_exit(&pdata->src2_lock);

	mutex_destroy(&pdata->src2_lock);

	kmem_free(pdata, sizeof (*pdata));

	am_set_src_data(handle, dir, NULL);

	ATRACE("am_src2_exit() done", NULL);

}	/* am_src2_exit() */

/*
 * am_src2_init()
 *
 * Description:
 *	Allocate memory for the sample rate conversion private data
 *	structure and initialize the mutex that guarantees we don't
 *	mess with buffers and parameters in the middle of a conversion.
 *	Because the current output sample depends on the current and
 *	past input samples we require room to store past input samples.
 *	Here we return the amount of extra room required in bytes.
 *	We initialise all we can at this point in order to keep the
 *	work required of am_src2_update() to a minimum.
 *
 *	CAUTION: This routine may be called only once without calling
 *	am_src2_exit(), otherwise we'll have a memory leak.
 *
 * Arguments:
 *	srchdl_t	handle		Mixer/src handle
 *	int		dir		Direction, AUDIO_PLAY or AUDIO_RECORD
 *
 * Returns:
 *	size_t		prebuffer	Prebuffer memory requirement
 */
static size_t
am_src2_init(srchdl_t handle, int dir)
{
	am_src2_data_t		*pdata;
	size_t			prebuffer;
	int			i;

	ATRACE("in am_src2_init()", handle);
	ATRACE_32("am_src2_init() direction", dir);

	/* Allocate src data structure */
	pdata = kmem_zalloc(sizeof (*pdata), KM_SLEEP);
	ATRACE("am_src2_init() new src data structure", pdata);

	/* Set up mutex */
	mutex_init(&pdata->src2_lock, NULL, MUTEX_DRIVER, NULL);

	/* Get the mutex */
	mutex_enter(&pdata->src2_lock);

	if (dir == AUDIO_PLAY) {
		/* Scale for 32-bit ints */
		prebuffer = (AM_SRC2_PBUFFER << AM_SRC2_SHIFT2);
		pdata->src2_pbsize = AM_SRC2_PBUFFER;
		pdata->src2_i_index = (pdata->src2_pbsize >> AM_SRC2_SHIFT1);
		pdata->src2_delta_c = 0;
		pdata->src2_cover = 0;
		pdata->src2_tables = kmem_alloc(sizeof (*pdata->src2_tables) *
			(AM_SRC2_CPZC + 1), KM_SLEEP);
		for (i = 0; i < AM_SRC2_CPZC + 1; i++) {
			pdata->src2_tables[i] =
				&_amsrc2tables[i * AM_SRC2_COFFS];
		}
	} else {
		ASSERT(dir == AUDIO_RECORD);
		/* Scale for 32-bit ints */
		prebuffer = (AM_SRC2_RBUFFER << AM_SRC2_SHIFT2);
		pdata->src2_pbsize = AM_SRC2_RBUFFER;
		pdata->src2_i_index = (pdata->src2_pbsize >> AM_SRC2_SHIFT1);
		pdata->src2_delta_c = 0;
		pdata->src2_delta_n = 0;
		pdata->src2_cover = 0;
		pdata->src2_table = _amsrc2table;
	}

	/* Set the data */
	am_set_src_data(handle, dir, pdata);

	/* Release the mutex */
	mutex_exit(&pdata->src2_lock);

	return (prebuffer);

}	/* am_src2_init() */

/*
 * am_src2_size()
 *
 * Description:
 *	Determine the size of a buffer, in bytes, needed to hold the number
 *	of "samples" when they are converted. We adjust the size based on
 *	the number of source hardware channels.
 *
 *	NOTE: This size of the buffer is based on 32-bit per sample.
 *
 * Arguments:
 *	srchdl_t	handle		Mixer/src handle
 *	audio_prinfo_t	*prinfo		Ptr to the channel's information
 *	int		dir		Direction, AUDIO_PLAY or AUDIO_RECORD
 *	int		samples		The number of samples
 *	int		hw_channels	Number of hardware channels
 *
 * Returns:
 *	size			The max # of bytes any sample rate conversion
 *				step could need in buffer space
 *	AUDIO_FAILURE		Couldn't find this size
 */
static size_t
am_src2_size(srchdl_t handle, audio_prinfo_t *prinfo, int dir, int samples,
    int hw_channels)
{
	am_src2_data_t		*pdata;
	size_t			size;

	ATRACE("in am_src2_size()", handle);
	ATRACE_32("am_src2_size() direction", dir);
	ATRACE_32("am_src2_size() samples", samples);
	ATRACE_32("am_src2_size() hw_channels", hw_channels);

	pdata = (am_src2_data_t *)am_get_src_data(handle, dir);
	if (pdata == NULL) {
		cmn_err(CE_WARN, "!amsrc2: src2_size() no pdata");
		return ((size_t)AUDIO_FAILURE);
	}

	ASSERT(pdata);

	mutex_enter(&pdata->src2_lock);
	ASSERT(pdata->src2_inFs);
	ASSERT(pdata->src2_outFs);
	ATRACE_32("am_src2_size() inFs", pdata->src2_inFs);
	ATRACE_32("am_src2_size() outFs", pdata->src2_outFs);

	/* Round up to maximum frame size if any leftover */
	size = samples * pdata->src2_outFs;
	if (size % pdata->src2_inFs) {
		size /= pdata->src2_inFs;
		size++;
	} else {
		size /= pdata->src2_inFs;
	}
	if (size % AUDIO_CHANNELS_STEREO) {
		size++;
	}

	/* Scale for 32-bit ints */
	size <<= AM_SRC2_SHIFT2;

	/* Now adjust for the number of channels */
	if (dir == AUDIO_PLAY) {
		if (prinfo->channels < hw_channels) {
			size *= hw_channels;
		}
	} else {
		ASSERT(dir == AUDIO_RECORD);
		if (prinfo->channels > hw_channels) {
			size *= prinfo->channels;
		}
	}

	mutex_exit(&pdata->src2_lock);

	ATRACE_32("am_src2_size() returned size", size);

	return (size);

}	/* am_src2_size() */

/*
 * am_src2_update()
 *
 * Description:
 *	Initialise the sample rate conversion private data structure. Here
 *	we (re-)initialise what we couldn't in am_src2_init().
 *
 * Arguments:
 *	srchdl_t	handle		Mixer/src handle
 *	audio_prinfo_t	*ch_prinfo	Ptr to the channel's information
 *	audio_prinfo_t	*hw_prinfo	Ptr to the Codec's information
 *	void		*src_info	Src information (not used)
 *	int		dir		Direction, AUDIO_PLAY or AUDIO_RECORD
 *
 * Returns:
 *	AUDIO_SUCCESS			Initialisation succeeded
 *	AUDIO_FAILURE			Initialisation failed
 */
/*ARGSUSED*/
static int
am_src2_update(srchdl_t handle, audio_prinfo_t *ch_prinfo, audio_prinfo_t
	*hw_prinfo, void *src_info, int dir)
{
	am_src2_data_t		*pdata;

	ATRACE("in am_src2_update()", handle);
	ATRACE_32("am_src2_update() direction", dir);
	ATRACE("am_src2_update() ch_prinfo", ch_prinfo);
	ATRACE("am_src2_update() hw_prinfo", hw_prinfo);

	/* Get src data structure */
	if ((pdata = (am_src2_data_t *)am_get_src_data(handle, dir)) == NULL) {
		cmn_err(CE_WARN, "!amsrc2: src2_update() no pdata");
		return (AUDIO_FAILURE);
	}

	mutex_enter(&pdata->src2_lock);

	ATRACE("am_src2_update() pdata", pdata);

	/*
	 * Set direction dependent data. Note: we should probably do some
	 * checking here to make sure sane samples rates are being used.
	 * Not as strict as amsrc1 but there should be something.
	 */
	if (dir == AUDIO_PLAY) {
		pdata->src2_inFs = ch_prinfo->sample_rate;
		pdata->src2_outFs = hw_prinfo->sample_rate;
		pdata->src2_csteps = ((pdata->src2_inFs << AM_SRC2_CPZC_SHIFT) /
			pdata->src2_outFs);
		pdata->src2_cmod = ((pdata->src2_inFs << AM_SRC2_CPZC_SHIFT) %
			pdata->src2_outFs);
	} else {
		ASSERT(dir == AUDIO_RECORD);
		pdata->src2_inFs = hw_prinfo->sample_rate;
		pdata->src2_outFs = ch_prinfo->sample_rate;
		pdata->src2_csteps = (pdata->src2_inFs * ch_prinfo->channels
			<< AM_SRC2_CPZC_SHIFT) / pdata->src2_outFs;
		pdata->src2_cmod = ((pdata->src2_inFs * ch_prinfo->channels
			<< AM_SRC2_CPZC_SHIFT) % pdata->src2_outFs);
		pdata->src2_tsteps = ((pdata->src2_outFs << AM_SRC2_CPZC_SHIFT)
			/ pdata->src2_inFs);
		/*
		 * Increment the filter step size if there is any left over.
		 * Otherwise we can overrun the end of the input signal when
		 * downsampling as the rounding errors accumulate.
		 */
		if ((pdata->src2_outFs << AM_SRC2_CPZC_SHIFT)
			% pdata->src2_inFs) {
			pdata->src2_tsteps++;
		}
	}

	ATRACE("am_src2_update() ch_prinfo", ch_prinfo);
	ATRACE_32("am_src2_update() src2_inFs", pdata->src2_inFs);
	ATRACE_32("am_src2_update() src2_outFs", pdata->src2_outFs);

	mutex_exit(&pdata->src2_lock);

	return (AUDIO_SUCCESS);

}	/* am_src2_update() */

/*
 * am_src2_up_m()
 *
 * Description:
 *	Carry out upsampling on a mono buffer.
 *
 * Arguments:
 *	am_src2_data_t	*parms		Conversion parameters structure
 *	int		inbuf		The input buffer to convert
 *	int		outbuf		The converted audio buffer
 *	int		samples		The number of samples to convert
 *
 * Returns:
 *	>= 0				The number of samples after conversion
 */
static int
am_src2_up_m(am_src2_data_t *parms, int *inbuf, int *outbuf, int samples)
{
	long long	sum;		/* Output sample value */
	int		k;		/* Coefficient counter */
	int		*t;		/* Pointer into table */
	int		count;		/* Output sample counter */
	int		s_index;	/* Input sample index */
	int		l_index;	/* Last sample index */
	int		c_index;	/* Starting coefficient index */
	int		rounding;	/* For rounding to nearest index */
	int		outFs;		/* Local copies of variables */
	int		cmod;
	int		cover;
	int		csteps;
	int		i_index;
	int		delta_c;
	int		**tables;

	/* Initialise */
	count = 0;
	cmod = parms->src2_cmod;
	cover = parms->src2_cover;
	tables = parms->src2_tables;
	csteps = parms->src2_csteps;
	i_index = parms->src2_i_index;
	delta_c = parms->src2_delta_c;
	i_index += (parms->src2_pbsize >> AM_SRC2_SHIFT1);
	outFs = parms->src2_outFs;
	l_index = samples + (parms->src2_pbsize >> AM_SRC2_SHIFT1);

	ATRACE("in am_src2_up_m()", NULL);
	ATRACE_32("in am_src2_up_m() cmod", cmod);
	ATRACE_32("in am_src2_up_m() cover", cover);
	ATRACE_32("in am_src2_up_m() csteps", csteps);
	ATRACE_32("in am_src2_up_m() i_index", i_index);
	ATRACE_32("in am_src2_up_m() delta_c", delta_c);
	ATRACE_32("in am_src2_up_m() outFs", outFs);
	ATRACE_32("in am_src2_up_m() l_index", l_index);
	ATRACE_32("in am_src2_up_m() samples", samples);

	/* Continue until the end */
	while (i_index < l_index) {

		/* Starting coefficient */
		c_index = AM_SRC2_CPZC - delta_c;
		t = tables[c_index];

		/* Starting sample */
		s_index = i_index + AM_SRC2_NZCS;

		/*
		 * Calculate output sample. Note we work from right to left
		 * starting with the rightmost sample and going backwards.
		 * We do it this way so a while loop can be used for better
		 * efficiency. This relies on the fact that t[0] is always
		 * zero.
		 */
		sum = 0;
		k = AM_SRC2_COFFS - 1;
		while (k) {
			sum += t[k--] * inbuf[s_index--];
		}

		/* Write out */
		outbuf[count++] = (sum >> AM_SRC2_COFF_SHIFT);

		/* Increment counters and pointers */
		cover += cmod;
		rounding = (cover << AM_SRC2_SHIFT1) / outFs;
		cover -= rounding * outFs;
		delta_c += rounding + csteps;
		i_index += (delta_c >> AM_SRC2_CPZC_SHIFT);
		delta_c &= AM_SRC2_CPZC_MASK;
	}

	/* Put back */
	parms->src2_i_index = i_index - l_index;
	parms->src2_delta_c = delta_c;
	parms->src2_cover = cover;

	/* Copy to front */
	bcopy(&inbuf[samples], inbuf, parms->src2_pbsize * sizeof (*inbuf));

	return (count);

}	/* am_src2_up_m() */

/*
 * am_src2_up_s()
 *
 * Description:
 *	Carry out upsampling on a stereo buffer.
 *
 * Arguments:
 *	am_src2_data_t	*parms		Conversion parameters structure
 *	int		inbuf		The input buffer to convert
 *	int		outbuf		The converted audio buffer
 *	int		samples		The number of samples to convert
 *
 * Returns:
 *	> 0				The number of samples after conversion
 */
static int
am_src2_up_s(am_src2_data_t *parms, int *inbuf, int *outbuf, int samples)
{
	long long	sum_l;		/* Output sample value */
	long long	sum_r;		/* Output sample value */
	int		c;		/* Coefficient value */
	int		*t;		/* Pointer into table */
	int		k;		/* Coefficient counter */
	int		count;		/* Output sample counter */
	int		s_index;	/* Input sample index */
	int		l_index;	/* Last sample index */
	int		c_index;	/* Starting coefficient index */
	int		rounding;	/* For rounding to nearest index */
	int		outFs;		/* Local copies of variables */
	int		cmod;
	int		cover;
	int		csteps;
	int		i_index;
	int		delta_c;
	int		**tables;

	/* Initialise */
	count = 0;
	cmod = parms->src2_cmod;
	cover = parms->src2_cover;
	tables = parms->src2_tables;
	csteps = parms->src2_csteps;
	i_index = parms->src2_i_index;
	delta_c = parms->src2_delta_c;
	i_index += (parms->src2_pbsize >> AM_SRC2_SHIFT1);
	outFs = parms->src2_outFs;
	l_index = samples + (parms->src2_pbsize >> AM_SRC2_SHIFT1);

	ATRACE("in am_src2_up_s()", NULL);
	ATRACE_32("in am_src2_up_s() cmod", cmod);
	ATRACE_32("in am_src2_up_s() cover", cover);
	ATRACE_32("in am_src2_up_s() csteps", csteps);
	ATRACE_32("in am_src2_up_s() i_index", i_index);
	ATRACE_32("in am_src2_up_s() delta_c", delta_c);
	ATRACE_32("in am_src2_up_s() outFs", outFs);
	ATRACE_32("in am_src2_up_s() l_index", l_index);
	ATRACE_32("in am_src2_up_s() samples", samples);

	/* Continue until the end */
	while (i_index < l_index) {

		/* Starting coefficient */
		c_index = AM_SRC2_CPZC - delta_c;
		t = tables[c_index];

		/* Starting sample */
		s_index = i_index + (AM_SRC2_NZCS << AM_SRC2_SHIFT1) + 1;

		/*
		 * Calculate output sample. Note we work from right to left
		 * starting with the rightmost sample and going backwards.
		 * We do it this way so a while loop can be used for better
		 * efficiency. This relies on the fact that t[0] is always
		 * zero.
		 */
		sum_l = sum_r = 0;
		k = AM_SRC2_COFFS - 1;
		while (k) {
			c = t[k--];
			sum_r += c * inbuf[s_index--];
			sum_l += c * inbuf[s_index--];
		}

		/* Write out */
		outbuf[count++] = (sum_l >> AM_SRC2_COFF_SHIFT);
		outbuf[count++] = (sum_r >> AM_SRC2_COFF_SHIFT);

		/* Increment counters and pointers */
		cover += cmod;
		rounding = (cover << AM_SRC2_SHIFT1) / outFs;
		cover -= rounding * outFs;
		delta_c += rounding + csteps;
		i_index += (delta_c >> AM_SRC2_CPZC_SHIFT);
		i_index += (i_index & AM_SRC2_STEREO_MASK);
		delta_c &= AM_SRC2_CPZC_MASK;
	}

	/* Put back */
	parms->src2_i_index = i_index - l_index;
	parms->src2_delta_c = delta_c;
	parms->src2_cover = cover;

	/* Copy to front */
	bcopy(&inbuf[samples], inbuf, parms->src2_pbsize * sizeof (*inbuf));

	return (count);

}	/* am_src2_up_s() */

/*
 * am_src2_dn_m()
 *
 * Description:
 *	Carry out downsampling on a mono buffer.
 *
 * Arguments:
 *	am_src2_data_t	*parms		Conversion parameters structure
 *	int		inbuf		The input buffer to convert
 *	int		outbuf		The converted audio buffer
 *	int		samples		The number of samples to convert
 *
 * Returns:
 *	> 0				The number of samples after conversion
 */
static int
am_src2_dn_m(am_src2_data_t *parms, int *inbuf, int *outbuf, int samples)
{
	long long	sum;		/* Output sample value */
	int		count;		/* Output sample counter */
	int		s_index;	/* Input sample index */
	int		l_index;	/* Last sample index */
	int		c_index;	/* Starting coefficient index */
	int		rounding;	/* For rounding to nearest index */
	int		outFs;		/* Local copies of variables */
	int		inFs;
	int		cmod;
	int		cover;
	int		csteps;
	int		tsteps;
	int		*table;
	int		i_index;
	int		delta_c;
	int		delta_n;

	/* Initialise */
	count = 0;
	cmod = parms->src2_cmod;
	table = parms->src2_table;
	cover = parms->src2_cover;
	tsteps = parms->src2_tsteps;
	csteps = parms->src2_csteps;
	i_index = parms->src2_i_index;
	delta_c = parms->src2_delta_c;
	delta_n = parms->src2_delta_n;
	i_index += (parms->src2_pbsize >> AM_SRC2_SHIFT1);
	outFs = parms->src2_outFs;
	inFs = parms->src2_inFs;
	l_index = samples + (parms->src2_pbsize >> AM_SRC2_SHIFT1);

	ATRACE("in am_src2_dn_m()", NULL);
	ATRACE_32("in am_src2_dn_m() cmod", cmod);
	ATRACE_32("in am_src2_dn_m() cover", cover);
	ATRACE_32("in am_src2_dn_m() csteps", csteps);
	ATRACE_32("in am_src2_dn_m() tsteps", tsteps);
	ATRACE_32("in am_src2_dn_m() i_index", i_index);
	ATRACE_32("in am_src2_dn_m() delta_c", delta_c);
	ATRACE_32("in am_src2_dn_m() delta_n", delta_n);
	ATRACE_32("in am_src2_dn_m() outFs", outFs);
	ATRACE_32("in am_src2_dn_m() inFs", inFs);
	ATRACE_32("in am_src2_dn_m() l_index", l_index);
	ATRACE_32("in am_src2_dn_m() samples", samples);

	/* Continue until the end */
	while (i_index < l_index) {

		/* Starting coefficient and sample */
		c_index = AM_SRC2_MIDDLE - delta_n;
		s_index = i_index - ((c_index - AM_SRC2_START) / tsteps);
		c_index -= tsteps * ((c_index - AM_SRC2_START) / tsteps);

		/* Calculate output sample */
		sum = 0;
		while (c_index <= AM_SRC2_END) {
			sum += (table[c_index] * inbuf[s_index++]);
			c_index += tsteps;
		}

		/* Write out */
		outbuf[count++] = ((sum * outFs / inFs) >> AM_SRC2_COFF_SHIFT);

		/* Increment counters and pointers */
		cover += cmod;
		rounding = (cover << AM_SRC2_SHIFT1) / outFs;
		cover -= rounding * outFs;
		delta_c += rounding + csteps;
		i_index += (delta_c >> AM_SRC2_CPZC_SHIFT);
		delta_c &= AM_SRC2_CPZC_MASK;
		delta_n = delta_c * outFs / inFs;
	}

	/* Put back */
	parms->src2_i_index = i_index - l_index;
	parms->src2_delta_c = delta_c;
	parms->src2_delta_n = delta_n;
	parms->src2_cover = cover;

	/* Copy to front */
	bcopy(&inbuf[samples], inbuf, parms->src2_pbsize * sizeof (*inbuf));

	return (count);

}	/* am_src2_dn_m() */

/*
 * am_src2_dn_s()
 *
 * Description:
 *	Carry out downsampling on a stereo buffer.
 *
 * Arguments:
 *	am_src2_data_t	*parms		Conversion parameters structure
 *	int		inbuf		The input buffer to convert
 *	int		outbuf		The converted audio buffer
 *	int		samples		The number of samples to convert
 *
 * Returns:
 *	> 0				The number of samples after conversion
 */
static int
am_src2_dn_s(am_src2_data_t *parms, int *inbuf, int *outbuf, int samples)
{
	long long	sum_l;		/* Output sample value */
	long long	sum_r;		/* Output sample value */
	int		c;		/* Coefficient value */
	int		count;		/* Output sample counter */
	int		s_index;	/* Input sample index */
	int		l_index;	/* Last sample index */
	int		c_index;	/* Starting coefficient index */
	int		rounding;	/* For rounding to nearest index */
	int		outFs;		/* Local copies of variables */
	int		inFs;
	int		cmod;
	int		cover;
	int		csteps;
	int		*table;
	int		tsteps;
	int		i_index;
	int		delta_c;
	int		delta_n;

	/* Initialise */
	count = 0;
	cmod = parms->src2_cmod;
	table = parms->src2_table;
	cover = parms->src2_cover;
	tsteps = parms->src2_tsteps;
	csteps = parms->src2_csteps;
	i_index = parms->src2_i_index;
	delta_c = parms->src2_delta_c;
	delta_n = parms->src2_delta_n;
	i_index += (parms->src2_pbsize >> AM_SRC2_SHIFT1);
	outFs = parms->src2_outFs;
	inFs = parms->src2_inFs;
	l_index = samples + (parms->src2_pbsize >> AM_SRC2_SHIFT1);

	ATRACE("in am_src2_dn_s()", NULL);
	ATRACE_32("in am_src2_dn_s() cmod", cmod);
	ATRACE_32("in am_src2_dn_s() cover", cover);
	ATRACE_32("in am_src2_dn_s() csteps", csteps);
	ATRACE_32("in am_src2_dn_s() tsteps", tsteps);
	ATRACE_32("in am_src2_dn_s() i_index", i_index);
	ATRACE_32("in am_src2_dn_s() delta_c", delta_c);
	ATRACE_32("in am_src2_dn_s() delta_n", delta_n);
	ATRACE_32("in am_src2_dn_s() outFs", outFs);
	ATRACE_32("in am_src2_dn_s() inFs", inFs);
	ATRACE_32("in am_src2_dn_s() l_index", l_index);
	ATRACE_32("in am_src2_dn_s() samples", samples);

	/* Continue until the end */
	while (i_index < l_index) {

		/* Starting coefficient and sample */
		c_index = AM_SRC2_MIDDLE - delta_n;
		s_index = i_index - (i_index & AM_SRC2_STEREO_MASK);
		s_index -= (((c_index - AM_SRC2_START) / tsteps) <<
			AM_SRC2_SHIFT1);
		c_index -= tsteps * ((c_index - AM_SRC2_START) / tsteps);

		sum_l = sum_r = 0;
		while (c_index <= AM_SRC2_END) {
			c = table[c_index];
			sum_l += c * inbuf[s_index++];
			sum_r += c * inbuf[s_index++];
			c_index += tsteps;
		}

		/* Write out */
		outbuf[count++] = (sum_l * outFs / inFs) >> AM_SRC2_COFF_SHIFT;
		outbuf[count++] = (sum_r * outFs / inFs) >> AM_SRC2_COFF_SHIFT;

		/* Increment counters and pointers */
		cover += cmod;
		rounding = (cover << AM_SRC2_SHIFT1) / outFs;
		cover -= rounding * outFs;
		delta_c += rounding + csteps;
		i_index += (delta_c >> AM_SRC2_CPZC_SHIFT);
		delta_c &= AM_SRC2_CPZC_MASK;
		delta_n = ((i_index & AM_SRC2_STEREO_MASK) <<
			(AM_SRC2_CPZC_SHIFT - 1)) + (delta_c >> AM_SRC2_SHIFT1);
		delta_n = delta_n * outFs / inFs;
	}

	/* Put back */
	parms->src2_i_index = i_index - l_index;
	parms->src2_delta_c = delta_c;
	parms->src2_delta_n = delta_n;
	parms->src2_cover = cover;

	/* Copy to front */
	bcopy(&inbuf[samples], inbuf, parms->src2_pbsize * sizeof (*inbuf));

	return (count);

}	/* am_src2_dn_s() */
