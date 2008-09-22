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


#include <sys/audio.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/disp.h>
#include <sys/ddi.h>
#include <sys/file.h>
#include <sys/id_space.h>
#include <sys/kmem.h>
#include <sys/lx_audio.h>
#include <sys/mixer.h>
#include <sys/modhash.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/sysmacros.h>
#include <sys/stropts.h>
#include <sys/types.h>
#include <sys/zone.h>

/* Properties used by the lx_audio driver */
#define	LXA_PROP_INPUTDEV		"inputdev"
#define	LXA_PROP_OUTPUTDEV		"outputdev"

/* default device paths used by this driver */
#define	LXA_DEV_DEFAULT			"/dev/audio"
#define	LXA_DEV_CUSTOM_DIR		"/dev/sound/"

/* maximum possible number of concurrent opens of this driver */
#define	LX_AUDIO_MAX_OPENS		1024

/*
 * these are default fragment size and fragment count values.
 * these values were chosen to make quake work well on my
 * laptop: 2Ghz Pentium M + NVIDIA GeForce Go 6400.
 *
 * for reference:
 * - 1 sec of stereo output at 44Khz is about 171 Kb of data
 * - 1 sec of mono output at 8Khz is about 8Kb of data
 */
#define	LXA_OSS_FRAG_SIZE		(1024)	/* 1/8 sec at 8Khz mono */
#define	LXA_OSS_FRAG_CNT		(1024 * 2)

/* maximum ammount of fragment memory we'll allow a process to mmap */
#define	LXA_OSS_FRAG_MEM		(1024 * 1024 * 2) /* 2Mb */

/* forward declarations */
typedef struct lxa_state lxa_state_t;
typedef struct lxa_zstate lxa_zstate_t;

/*
 * Structure and enum declarations
 */
typedef enum {
	LXA_TYPE_INVALID	= 0,
	LXA_TYPE_AUDIO		= 1,	/* audio device */
	LXA_TYPE_AUDIOCTL	= 2	/* audio control/mixer device */
} lxa_dev_type_t;

struct lxa_zstate {
	char			*lxa_zs_zonename;

	/*
	 * we could store the input/output audio device setting here,
	 * but instead we're keeing them as device node properties
	 * so that a user can easily see the audio configuration for
	 * a zone via prtconf.
	 */

	/*
	 * OSS doesn't support multiple opens of the audio device.
	 * (multiple opens of the mixer device are supported.)
	 * so here we'll keep a pointer to any open input/output
	 * streams.  (OSS does support two opens if one is for input
	 * and the other is for output.)
	 */
	lxa_state_t		*lxa_zs_istate;
	lxa_state_t		*lxa_zs_ostate;

	/*
	 * we need to cache channel gain and balance.  channel gain and
	 * balance map to PCM volume in OSS, which are supposedly a property
	 * of the underlying hardware.  but in solaris, channels are
	 * implemented in software and only exist when an audio device
	 * is actually open.  (each open returns a unique channel.)  OSS
	 * apps will expect consistent PCM volume set/get operations to
	 * work even if no audio device is open.  hence, if no underlying
	 * device is open we need to cache the gain and balance setting.
	 */
	lxa_mixer_levels_t	lxa_zs_pcm_levels;
};

struct lxa_state {
	lxa_zstate_t	*lxas_zs;	/* zone state pointer */

	dev_t		lxas_dev_old;	/* dev_t used to open the device */
	dev_t		lxas_dev_new;	/* new dev_t assigned to an open */
	int		lxas_flags;	/* original flags passed to open */
	lxa_dev_type_t	lxas_type;	/* type of device that was opened */

	int		lxas_devs_same;	/* input and output device the same? */

	/* input device variables */
	ldi_handle_t	lxas_idev_lh;		/* ldi handle for access */
	int		lxas_idev_flags;	/* flags used for open */

	/* output device variables */
	ldi_handle_t	lxas_odev_lh;		/* ldi handle for access */
	int		lxas_odev_flags;	/* flags used for open */

	/*
	 * since we support multiplexing of devices we need to remember
	 * certain parameters about the devices
	 */
	uint_t		lxas_hw_features;
	uint_t		lxas_sw_features;

	uint_t		lxas_frag_size;
	uint_t		lxas_frag_cnt;

	/*
	 * members needed to support mmap device access.  note that to
	 * simplifly things we only support one mmap access per open.
	 */
	ddi_umem_cookie_t	lxas_umem_cookie;
	char			*lxas_umem_ptr;
	size_t			lxas_umem_len;
	kthread_t		*lxas_mmap_thread;
	int			lxas_mmap_thread_running;
	int			lxas_mmap_thread_exit;
	int			lxas_mmap_thread_frag;
};

/*
 * Global variables
 */
dev_info_t	*lxa_dip = NULL;
kmutex_t	lxa_lock;
id_space_t	*lxa_minor_id = NULL;
mod_hash_t	*lxa_state_hash = NULL;
mod_hash_t	*lxa_zstate_hash = NULL;
size_t		lxa_state_hash_size = 15;
size_t		lxa_zstate_hash_size = 15;
size_t		lxa_registered_zones = 0;

/*
 * function declarations
 */
static void lxa_mmap_output_disable(lxa_state_t *);

/*
 * functions
 */
static void
lxa_state_close(lxa_state_t *lxa_state)
{
	lxa_zstate_t		*lxa_zs = lxa_state->lxas_zs;
	minor_t			minor = getminor(lxa_state->lxas_dev_new);

	/* disable any mmap output that might still be going on */
	lxa_mmap_output_disable(lxa_state);

	/*
	 * if this was the active input/output device, unlink it from
	 * the global zone state so that other opens of the audio device
	 * can now succeed.
	 */
	mutex_enter(&lxa_lock);
	if (lxa_zs->lxa_zs_istate == lxa_state)
		lxa_zs->lxa_zs_istate = NULL;
	if (lxa_zs->lxa_zs_ostate == lxa_state) {
		lxa_zs->lxa_zs_ostate = NULL;
	}
	mutex_exit(&lxa_lock);

	/* remove this state structure from the hash (if it's there) */
	(void) mod_hash_remove(lxa_state_hash,
	    (mod_hash_key_t)(uintptr_t)minor, (mod_hash_val_t *)&lxa_state);

	/* close any audio device that we have open */
	if (lxa_state->lxas_idev_lh != NULL)
		(void) ldi_close(lxa_state->lxas_idev_lh,
		    lxa_state->lxas_idev_flags, kcred);
	if (lxa_state->lxas_odev_lh != NULL)
		(void) ldi_close(lxa_state->lxas_odev_lh,
		    lxa_state->lxas_odev_flags, kcred);

	/* free up any memory allocated by mmaps */
	if (lxa_state->lxas_umem_cookie != NULL)
		ddi_umem_free(lxa_state->lxas_umem_cookie);

	/* release the id associated with this state structure */
	id_free(lxa_minor_id, minor);

	kmem_free(lxa_state, sizeof (*lxa_state));
}

static char *
getzonename(void)
{
	return (curproc->p_zone->zone_name);
}

static void
strfree(char *str)
{
	kmem_free(str, strlen(str) + 1);
}

static char *
strdup(char *str)
{
	int	n = strlen(str);
	char	*ptr = kmem_alloc(n + 1, KM_SLEEP);
	bcopy(str, ptr, n + 1);
	return (ptr);
}

static char *
lxa_devprop_name(char *zname, char *pname)
{
	char	*zpname;
	int	n;

	ASSERT((pname != NULL) && (zname != NULL));

	/* prepend the zone name to the property name */
	n = snprintf(NULL, 0, "%s_%s", zname, pname) + 1;
	zpname = kmem_alloc(n, KM_SLEEP);
	(void) snprintf(zpname, n, "%s_%s", zname, pname);

	return (zpname);
}

static int
lxa_devprop_verify(char *pval)
{
	int	n;

	ASSERT(pval != NULL);

	if (strcmp(pval, "default") == 0)
		return (0);

	/* make sure the value is an integer */
	for (n = 0; pval[n] != '\0'; n++) {
		if ((pval[n] < '0') && (pval[n] > '9')) {
			return (-1);
		}
	}

	return (0);
}

static char *
lxa_devprop_lookup(char *zname, char *pname, lxa_dev_type_t lxa_type)
{
	char		*zprop_name, *pval;
	char		*dev_path;
	int		n, rv;

	ASSERT((pname != NULL) && (zname != NULL));
	ASSERT((lxa_type == LXA_TYPE_AUDIO) || (lxa_type == LXA_TYPE_AUDIOCTL));

	zprop_name = lxa_devprop_name(zname, pname);

	/* attempt to lookup the property */
	rv = ddi_prop_lookup_string(DDI_DEV_T_ANY, lxa_dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, zprop_name, &pval);
	strfree(zprop_name);

	if (rv != DDI_PROP_SUCCESS)
		return (NULL);

	if (lxa_devprop_verify(pval) != 0) {
		ddi_prop_free(pval);
		return (NULL);
	}

	if (strcmp(pval, "none") == 0) {
		/* there is no audio device specified */
		return (NULL);
	} else if (strcmp(pval, "default") == 0) {
		/* use the default audio device on the system */
		dev_path = strdup(LXA_DEV_DEFAULT);
	} else {
		/* a custom audio device was specified, generate a path */
		n = snprintf(NULL, 0, "%s%s", LXA_DEV_CUSTOM_DIR, pval) + 1;
		dev_path = kmem_alloc(n, KM_SLEEP);
		(void) snprintf(dev_path, n, "%s%s", LXA_DEV_CUSTOM_DIR, pval);
	}
	ddi_prop_free(pval);

	/*
	 * if this is an audio control device so we need to append
	 * "ctl" to the path
	 */
	if (lxa_type == LXA_TYPE_AUDIOCTL) {
		char	*tmp;
		n = snprintf(NULL, 0, "%s%s", dev_path, "ctl") + 1;
		tmp = kmem_alloc(n, KM_SLEEP);
		(void) snprintf(tmp, n, "%s%s", dev_path, "ctl");
		strfree(dev_path);
		dev_path = tmp;
	}

	return (dev_path);
}

static int
lxa_dev_getfeatures(lxa_state_t *lxa_state)
{
	audio_info_t	ai_idev, ai_odev;
	int		n, rv;

	/* set a default fragment size */
	lxa_state->lxas_frag_size = LXA_OSS_FRAG_SIZE;
	lxa_state->lxas_frag_cnt = LXA_OSS_FRAG_CNT;

	/* get info for the currently open audio devices */
	if ((lxa_state->lxas_idev_lh != NULL) &&
	    ((rv = ldi_ioctl(lxa_state->lxas_idev_lh,
	    AUDIO_GETINFO, (intptr_t)&ai_idev, FKIOCTL, kcred, &n)) != 0))
		return (rv);
	if ((lxa_state->lxas_odev_lh != NULL) &&
	    ((rv = ldi_ioctl(lxa_state->lxas_odev_lh,
	    AUDIO_GETINFO, (intptr_t)&ai_odev, FKIOCTL, kcred, &n)) != 0))
		return (rv);

	/* if we're only open for reading or writing then it's easy */
	if (lxa_state->lxas_idev_lh == NULL) {
		lxa_state->lxas_sw_features = ai_odev.sw_features;
		lxa_state->lxas_hw_features = ai_odev.hw_features;
		return (0);
	} else if (lxa_state->lxas_odev_lh == NULL) {
		lxa_state->lxas_sw_features = ai_idev.sw_features;
		lxa_state->lxas_hw_features = ai_idev.hw_features;
		return (0);
	}

	/*
	 * well if we're open for reading and writing but the underlying
	 * device is the same then it's also pretty easy
	 */
	if (lxa_state->lxas_devs_same) {
		if ((ai_odev.sw_features != ai_idev.sw_features) ||
		    (ai_odev.hw_features != ai_idev.hw_features)) {
			zcmn_err(getzoneid(), CE_WARN, "lx_audio error: "
			    "audio device reported inconsistent features");
			return (EIO);
		}
		lxa_state->lxas_sw_features = ai_odev.sw_features;
		lxa_state->lxas_hw_features = ai_odev.hw_features;
		return (0);
	}

	/*
	 * figure out which software features we're going to support.
	 * we will report a feature as supported if both the input
	 * and output device support it.
	 */
	lxa_state->lxas_sw_features = 0;
	n = ai_idev.sw_features & ai_odev.sw_features;
	if (n & AUDIO_SWFEATURE_MIXER)
		lxa_state->lxas_sw_features |= AUDIO_SWFEATURE_MIXER;

	/*
	 * figure out which hardware features we're going to support.
	 * for a first pass we will report a feature as supported if
	 * both the input and output device support it.
	 */
	lxa_state->lxas_hw_features = 0;
	n = ai_idev.hw_features & ai_odev.hw_features;
	if (n & AUDIO_HWFEATURE_MSCODEC)
		lxa_state->lxas_hw_features |= AUDIO_HWFEATURE_MSCODEC;

	/*
	 * if we made it here then we have different audio input and output
	 * devices.  this will allow us to report support for additional
	 * hardware features that may not supported by just the input or
	 * output device alone.
	 */

	/* always report tha we support both playback and recording */
	lxa_state->lxas_hw_features =
	    AUDIO_HWFEATURE_PLAY | AUDIO_HWFEATURE_RECORD;

	/* always report full duplex support */
	lxa_state->lxas_hw_features = AUDIO_HWFEATURE_DUPLEX;

	/* never report that we have input to output loopback support */
	ASSERT((lxa_state->lxas_hw_features & AUDIO_HWFEATURE_IN2OUT) == 0);
	return (0);
}

static int
lxa_dev_open(lxa_state_t *lxa_state)
{
	char		*idev, *odev;
	int		flags, rv;
	ldi_handle_t	lh;
	ldi_ident_t	li = NULL;

	ASSERT((lxa_state->lxas_type == LXA_TYPE_AUDIO) ||
	    (lxa_state->lxas_type == LXA_TYPE_AUDIOCTL));

	/*
	 * check if we have configuration properties for this zone.
	 * if we don't then audio isn't supported in this zone.
	 */
	idev = lxa_devprop_lookup(getzonename(), LXA_PROP_INPUTDEV,
	    lxa_state->lxas_type);
	odev = lxa_devprop_lookup(getzonename(), LXA_PROP_OUTPUTDEV,
	    lxa_state->lxas_type);

	/* make sure there is at least one device to read from or write to */
	if ((idev == NULL) && (odev == NULL))
		return (ENODEV);

	/* see if the input and output devices are actually the same device */
	if (((idev != NULL) && (odev != NULL)) &&
	    (strcmp(idev, odev) == 0))
		lxa_state->lxas_devs_same = 1;

	/* we don't respect FEXCL */
	flags = lxa_state->lxas_flags & ~FEXCL;
	if (lxa_state->lxas_type == LXA_TYPE_AUDIO) {
		/*
		 * if we're opening audio devices then we need to muck
		 * with the FREAD/FWRITE flags.
		 *
		 * certain audio device may only support input or output
		 * (but not both.)  so if we're multiplexing input/output
		 * to different devices we need to make sure we don't try
		 * and open the output device for reading and the input
		 * device for writing.
		 *
		 * if we're using the same device for input/output we still
		 * need to do this because some audio devices won't let
		 * themselves be opened multiple times for read access.
		 */
		lxa_state->lxas_idev_flags = flags & ~FWRITE;
		lxa_state->lxas_odev_flags = flags & ~FREAD;

		/* make sure we have devices to read from and write to */
		if (((flags & FREAD) && (idev == NULL)) ||
		    ((flags & FWRITE) && (odev == NULL))) {
			rv = ENODEV;
			goto out;
		}
	} else {
		lxa_state->lxas_idev_flags = lxa_state->lxas_odev_flags = flags;
	}

	/* get an ident to open the devices */
	if (ldi_ident_from_dev(lxa_state->lxas_dev_new, &li) != 0) {
		rv = ENODEV;
		goto out;
	}

	/* open the input device */
	lxa_state->lxas_idev_lh = NULL;
	if (((lxa_state->lxas_type == LXA_TYPE_AUDIOCTL) ||
	    (lxa_state->lxas_idev_flags & FREAD)) &&
	    (idev != NULL)) {
		rv = ldi_open_by_name(idev, lxa_state->lxas_idev_flags,
		    kcred, &lh, li);
		if (rv != 0) {
			zcmn_err(getzoneid(), CE_WARN, "lxa_open_dev: "
			    "unable to open audio device: %s", idev);
			zcmn_err(getzoneid(), CE_WARN, "lxa_open_dev: "
			    "possible zone audio configuration error");
			goto out;
		}
		lxa_state->lxas_idev_lh = lh;
	}

	/* open the output device */
	lxa_state->lxas_odev_lh = NULL;
	if (((lxa_state->lxas_type == LXA_TYPE_AUDIOCTL) ||
	    (lxa_state->lxas_odev_flags & FWRITE)) &&
	    (odev != NULL)) {
		rv = ldi_open_by_name(odev, lxa_state->lxas_odev_flags,
		    kcred, &lh, li);
		if (rv != 0) {
			/*
			 * If this open failed and we previously opened an
			 * input device, it is the responsibility of the
			 * caller to close that device after we return
			 * failure here.
			 */
			zcmn_err(getzoneid(), CE_WARN, "lxa_open_dev: "
			    "unable to open audio device: %s", odev);
			zcmn_err(getzoneid(), CE_WARN, "lxa_open_dev: "
			    "possible zone audio configuration error");
			goto out;
		}
		lxa_state->lxas_odev_lh = lh;
	}

	/* free up stuff */
out:
	if (li != NULL)
		ldi_ident_release(li);
	if (idev != NULL)
		strfree(idev);
	if (odev != NULL)
		strfree(odev);

	return (rv);
}

void
lxa_mmap_thread_exit(lxa_state_t *lxa_state)
{
	mutex_enter(&lxa_lock);
	lxa_state->lxas_mmap_thread = NULL;
	lxa_state->lxas_mmap_thread_frag = 0;
	lxa_state->lxas_mmap_thread_running = 0;
	lxa_state->lxas_mmap_thread_exit = 0;
	mutex_exit(&lxa_lock);
	thread_exit();
	/*NOTREACHED*/
}

void
lxa_mmap_thread(lxa_state_t *lxa_state)
{
	struct uio	uio, uio_null;
	iovec_t		iovec, iovec_null;
	uint_t		bytes_per_sec, usec_per_frag, ticks_per_frag;
	int		rv, junk, eof, retry;
	audio_info_t	ai;

	/* we better be setup for writing to the output device */
	ASSERT((lxa_state->lxas_flags & FWRITE) != 0);
	ASSERT(lxa_state->lxas_odev_lh != NULL);

	/* setup a uio to output one fragment */
	uio.uio_iov = &iovec;
	uio.uio_iovcnt = 1;
	uio.uio_offset = 0;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_extflg = 0;
	uio.uio_llimit = MAXOFFSET_T;

	/* setup a uio to output a eof (a fragment with a length of 0) */
	uio_null.uio_iov = &iovec_null;
	uio_null.uio_iov->iov_len = 0;
	uio_null.uio_iov->iov_base = NULL;
	uio_null.uio_iovcnt = 1;
	uio_null.uio_offset = 0;
	uio_null.uio_segflg = UIO_SYSSPACE;
	uio_null.uio_fmode = 0;
	uio_null.uio_extflg = 0;
	uio_null.uio_llimit = MAXOFFSET_T;
	uio_null.uio_resid = 0;

lxa_mmap_thread_top:
	ASSERT(!MUTEX_HELD(&lxa_lock));

	/* first drain any pending audio output */
	if ((rv = ldi_ioctl(lxa_state->lxas_odev_lh,
	    AUDIO_DRAIN, NULL, FKIOCTL, kcred, &junk)) != 0) {
		cmn_err(CE_WARN, "lxa_mmap_thread: "
		    "AUDIO_DRAIN failed, aborting audio output");
		lxa_mmap_thread_exit(lxa_state);
		/*NOTREACHED*/
	}

	/*
	 * we depend on the ai.play.eof value to keep track of
	 * audio output progress so reset it here.
	 */
	AUDIO_INITINFO(&ai);
	ai.play.eof = 0;
	if ((rv = ldi_ioctl(lxa_state->lxas_odev_lh,
	    AUDIO_SETINFO, (intptr_t)&ai, FKIOCTL, kcred, &junk)) != 0) {
		cmn_err(CE_WARN, "lxa_mmap_thread: "
		    "AUDIO_SETINFO failed, aborting audio output");
		lxa_mmap_thread_exit(lxa_state);
		/*NOTREACHED*/
	}

	/*
	 * we're going to need to know the sampling rate and number
	 * of output channels to estimate how long we can sleep between
	 * requests.
	 */
	if ((rv = ldi_ioctl(lxa_state->lxas_odev_lh, AUDIO_GETINFO,
	    (intptr_t)&ai, FKIOCTL, kcred, &junk)) != 0) {
		cmn_err(CE_WARN, "lxa_mmap_thread: "
		    "AUDIO_GETINFO failed, aborting audio output");
		lxa_mmap_thread_exit(lxa_state);
		/*NOTREACHED*/
	}

	/* estimate how many ticks it takes to output a fragment of data */
	bytes_per_sec = (ai.play.sample_rate * ai.play.channels *
	    ai.play.precision) / 8;
	usec_per_frag = MICROSEC * lxa_state->lxas_frag_size / bytes_per_sec;
	ticks_per_frag = drv_usectohz(usec_per_frag);

	/* queue up three fragments of of data into the output stream */
	eof = 3;

	/* sanity check the eof value */
	ASSERT(ai.play.eof == 0);
	ai.play.eof = 0;

	/* we always start audio output at fragment 0 */
	mutex_enter(&lxa_lock);
	lxa_state->lxas_mmap_thread_frag = 0;

	/*
	 * we shouldn't have allowed the mapping if it isn't a multiple
	 * of the fragment size
	 */
	ASSERT((lxa_state->lxas_umem_len % lxa_state->lxas_frag_size) == 0);

	while (!lxa_state->lxas_mmap_thread_exit) {
		size_t start, end;

		/*
		 * calculate the start and ending offsets of the next
		 * fragment to output
		 */
		start = lxa_state->lxas_mmap_thread_frag *
		    lxa_state->lxas_frag_size;
		end = start + lxa_state->lxas_frag_size;

		ASSERT(start < lxa_state->lxas_umem_len);
		ASSERT(end <= lxa_state->lxas_umem_len);

		/* setup the uio to output one fragment of audio */
		uio.uio_resid = end - start;
		uio.uio_iov->iov_len = end - start;
		uio.uio_iov->iov_base = &lxa_state->lxas_umem_ptr[start];

		/* increment the current fragment index */
		lxa_state->lxas_mmap_thread_frag =
		    (lxa_state->lxas_mmap_thread_frag + 1) %
		    (lxa_state->lxas_umem_len / lxa_state->lxas_frag_size);

		/* drop the audio lock before actually outputting data */
		mutex_exit(&lxa_lock);

		/*
		 * write the fragment of audio data to the device stream
		 * then write a eof to the stream to tell the device to
		 * increment ai.play.eof when it's done processing the
		 * fragment we just wrote
		 */
		if ((rv = ldi_write(lxa_state->lxas_odev_lh,
		    &uio, kcred)) != 0) {
			cmn_err(CE_WARN, "lxa_mmap_thread: "
			    "ldi_write() failed (%d), "
			    "resetting audio output", rv);
			goto lxa_mmap_thread_top;
		}
		if ((rv = ldi_write(lxa_state->lxas_odev_lh,
		    &uio_null, kcred)) != 0) {
			cmn_err(CE_WARN, "lxa_mmap_thread: "
			    "ldi_write(eof) failed (%d), "
			    "resetting audio output", rv);
			goto lxa_mmap_thread_top;
		}

		/*
		 * we want to avoid buffer underrun so ensure that
		 * there is always at least one fragment of data in the
		 * output stream.
		 */
		mutex_enter(&lxa_lock);
		if (--eof > 0) {
			continue;
		}

		/*
		 * now we wait until the audio device has finished outputting
		 * at least one fragment of data.
		 */
		retry = 0;
		while (!lxa_state->lxas_mmap_thread_exit && (eof == 0)) {
			uint_t ai_eof_old = ai.play.eof;

			mutex_exit(&lxa_lock);

			/*
			 * delay for the number of ticks it takes
			 * to output one fragment of data
			 */
			if (ticks_per_frag > 0)
				delay(ticks_per_frag);

			/* check if we've managed to output any fragments */
			if ((rv = ldi_ioctl(lxa_state->lxas_odev_lh,
			    AUDIO_GETINFO, (intptr_t)&ai,
			    FKIOCTL, kcred, &junk)) != 0) {
				cmn_err(CE_WARN, "lxa_mmap_thread: "
				    "AUDIO_GETINFO failed (%d), "
				    "resetting audio output", rv);
				/* re-start mmap audio output */
				goto lxa_mmap_thread_top;
			}

			if (ai_eof_old == ai.play.eof) {
				/* institute a random retry limit */
				if (retry++ < 100) {
					mutex_enter(&lxa_lock);
					continue;
				}
				cmn_err(CE_WARN, "lxa_mmap_thread: "
				    "output stalled, "
				    "resetting audio output");
				/* re-start mmap audio output */
				goto lxa_mmap_thread_top;
			}

			if (ai.play.eof > ai_eof_old) {
				eof = ai.play.eof - ai_eof_old;
			} else {
				/* eof counter wrapped around */
				ASSERT(ai_eof_old < ai.play.eof);
				eof = ai.play.eof + (ai_eof_old - UINTMAX_MAX);
			}
			/* we're done with this loop so re-aquire the lock */
			ASSERT(eof != 0);
			mutex_enter(&lxa_lock);
		}
	}
	mutex_exit(&lxa_lock);
	lxa_mmap_thread_exit(lxa_state);
	/*NOTREACHED*/
}

static void
lxa_mmap_output_disable(lxa_state_t *lxa_state)
{
	kt_did_t tid;

	mutex_enter(&lxa_lock);

	/* if the output thread isn't running there's nothing to do */
	if (lxa_state->lxas_mmap_thread_running == 0) {
		mutex_exit(&lxa_lock);
		return;
	}

	/* tell the pcm mmap output thread to exit */
	lxa_state->lxas_mmap_thread_exit = 1;

	/* wait for the mmap output thread to exit */
	tid = lxa_state->lxas_mmap_thread->t_did;
	mutex_exit(&lxa_lock);
	thread_join(tid);
}

static void
lxa_mmap_output_enable(lxa_state_t *lxa_state)
{
	mutex_enter(&lxa_lock);

	/* if the output thread is already running there's nothing to do */
	if (lxa_state->lxas_mmap_thread_running != 0) {
		mutex_exit(&lxa_lock);
		return;
	}

	/* setup output state */
	lxa_state->lxas_mmap_thread_running = 1;
	lxa_state->lxas_mmap_thread_exit = 0;
	lxa_state->lxas_mmap_thread_frag = 0;

	/* kick off a thread to do the mmap pcm output */
	lxa_state->lxas_mmap_thread = thread_create(NULL, 0,
	    (void (*)())lxa_mmap_thread, lxa_state,
	    0, &p0, TS_RUN, minclsyspri);
	ASSERT(lxa_state->lxas_mmap_thread != NULL);

	mutex_exit(&lxa_lock);
}

static int
lxa_ioc_mmap_output(lxa_state_t *lxa_state, intptr_t arg, int mode)
{
	uint_t	trigger;

	/* we only support output via mmap */
	if ((lxa_state->lxas_flags & FWRITE) == 0)
		return (EINVAL);

	/* if the user hasn't mmap the device then there's nothing to do */
	if (lxa_state->lxas_umem_cookie == NULL)
		return (EINVAL);

	/* copy in the request */
	if (ddi_copyin((void *)arg, &trigger, sizeof (trigger), mode) != 0)
		return (EFAULT);

	/* a zero value disables output */
	if (trigger == 0) {
		lxa_mmap_output_disable(lxa_state);
		return (0);
	}

	/* a non-zero value enables output */
	lxa_mmap_output_enable(lxa_state);
	return (0);
}

static int
lxa_ioc_mmap_ptr(lxa_state_t *lxa_state, intptr_t arg, int mode)
{
	int	ptr;

	/* we only support output via mmap */
	if ((lxa_state->lxas_flags & FWRITE) == 0)
		return (EINVAL);

	/* if the user hasn't mmap the device then there's nothing to do */
	if (lxa_state->lxas_umem_cookie == NULL)
		return (EINVAL);

	/* if the output thread isn't running then there's nothing to do */
	if (lxa_state->lxas_mmap_thread_running == 0)
		return (EINVAL);

	mutex_enter(&lxa_lock);
	ptr = lxa_state->lxas_mmap_thread_frag * lxa_state->lxas_frag_size;
	mutex_exit(&lxa_lock);

	if (ddi_copyout(&ptr, (void *)arg, sizeof (ptr), mode) != 0)
		return (EFAULT);

	return (0);
}

static int
lxa_ioc_get_frag_info(lxa_state_t *lxa_state, intptr_t arg, int mode)
{
	lxa_frag_info_t	fi;

	fi.lxa_fi_size = lxa_state->lxas_frag_size;
	fi.lxa_fi_cnt = lxa_state->lxas_frag_cnt;

	if (ddi_copyout(&fi, (void *)arg, sizeof (fi), mode) != 0)
		return (EFAULT);

	return (0);
}

static int
lxa_ioc_set_frag_info(lxa_state_t *lxa_state, intptr_t arg, int mode)
{
	lxa_frag_info_t	fi;

	/* if the device is mmaped we can't change the fragment settings */
	if (lxa_state->lxas_umem_cookie != NULL)
		return (EINVAL);

	/* copy in the request */
	if (ddi_copyin((void *)arg, &fi, sizeof (fi), mode) != 0)
		return (EFAULT);

	/* do basic bounds checking */
	if ((fi.lxa_fi_cnt == 0) || (fi.lxa_fi_size < 16))
		return (EINVAL);

	/* don't accept size values less than 16 */

	lxa_state->lxas_frag_size = fi.lxa_fi_size;
	lxa_state->lxas_frag_cnt = fi.lxa_fi_cnt;

	return (0);
}

static int
lxa_audio_drain(lxa_state_t *lxa_state)
{
	int	junk;

	/* only applies to output buffers */
	if (lxa_state->lxas_odev_lh == NULL)
		return (EINVAL);

	/* can't fail so ignore the return value */
	(void) ldi_ioctl(lxa_state->lxas_odev_lh, AUDIO_DRAIN, NULL,
	    FKIOCTL, kcred, &junk);
	return (0);
}

/*
 * lxa_audio_info_merge() usage notes:
 *
 * - it's important to make sure NOT to get the ai_idev and ai_odev
 *   parameters mixed up when calling lxa_audio_info_merge().
 *
 * - it's important for the caller to make sure that AUDIO_GETINFO
 *   was called for the input device BEFORE the output device.  (see
 *   the comments for merging the monitor_gain setting to see why.)
 */
static void
lxa_audio_info_merge(lxa_state_t *lxa_state,
    audio_info_t *ai_idev, audio_info_t *ai_odev, audio_info_t *ai_merged)
{
	/* if we're not setup for output return the intput device info */
	if (lxa_state->lxas_odev_lh == NULL) {
		*ai_merged = *ai_idev;
		return;
	}

	/* if we're not setup for input return the output device info */
	if (lxa_state->lxas_idev_lh == NULL) {
		*ai_merged = *ai_odev;
		return;
	}

	/* get record values from the input device */
	ai_merged->record = ai_idev->record;

	/* get play values from the output device */
	ai_merged->play = ai_odev->play;

	/* muting status only matters for the output device */
	ai_merged->output_muted = ai_odev->output_muted;

	/* we don't support device reference counts, always return 1 */
	ai_merged->ref_cnt = 1;

	/*
	 * for supported hw/sw features report the combined feature
	 * set we calcuated out earlier.
	 */
	ai_merged->hw_features = lxa_state->lxas_hw_features;
	ai_merged->sw_features = lxa_state->lxas_sw_features;

	if (!lxa_state->lxas_devs_same) {
		/*
		 * if the input and output devices are different
		 * physical devices then we don't support input to
		 * output loopback so we always report the input
		 * to output loopback gain to be zero.
		 */
		ai_merged->monitor_gain = 0;
	} else {
		/*
		 * the intput and output devices are actually the
		 * same physical device.  hence it probably supports
		 * intput to output loopback.  regardless we should
		 * pass back the intput to output gain reported by
		 * the device.  when we pick a value to passback we
		 * use the output device value since that was
		 * the most recently queried.  (we base this
		 * decision on the assumption that io gain is
		 * actually hardware setting in the device and
		 * hence if it is changed on one open instance of
		 * the device the change will be visable to all
		 * other instances of the device.)
		 */
		ai_merged->monitor_gain = ai_odev->monitor_gain;
	}

	/*
	 * for currently enabled software features always return the
	 * merger of the two.  (of course the enabled software features
	 * for the input and output devices should alway be the same,
	 * so if it isn't complain.)
	 */
	if (ai_idev->sw_features_enabled != ai_odev->sw_features_enabled)
		zcmn_err(getzoneid(), CE_WARN, "lx_audio: "
		    "unexpected sofware feature state");
	ai_merged->sw_features_enabled =
	    ai_idev->sw_features_enabled & ai_odev->sw_features_enabled;
}

static int
lxa_audio_setinfo(lxa_state_t *lxa_state, int cmd, intptr_t arg,
    int mode)
{
	audio_info_t	ai, ai_null, ai_idev, ai_odev;
	int		rv, junk;

	/* copy in the request */
	if (ddi_copyin((void *)arg, &ai, sizeof (ai), mode) != 0)
		return (EFAULT);

	/*
	 * if the caller is attempting to enable a software feature that
	 * we didn't report as supported the return an error
	 */
	if ((ai.sw_features_enabled != -1) &&
	    (ai.sw_features_enabled & ~lxa_state->lxas_sw_features))
		return (EINVAL);

	/*
	 * if a process has mmaped this device then we don't allow
	 * changes to the play.eof field (since mmap output depends
	 * on this field.
	 */
	if ((lxa_state->lxas_umem_cookie != NULL) &&
	    (ai.play.eof != -1))
		return (EIO);

	/* initialize the new requests */
	AUDIO_INITINFO(&ai_null);
	ai_idev = ai_odev = ai;

	/* remove audio input settings from the output device request */
	ai_odev.record = ai_null.record;

	/* remove audio output settings from the input device request */
	ai_idev.play = ai_null.play;
	ai_idev.output_muted = ai_null.output_muted;

	/* apply settings to the intput device */
	if ((lxa_state->lxas_idev_lh != NULL) &&
	    ((rv = ldi_ioctl(lxa_state->lxas_idev_lh, cmd,
	    (intptr_t)&ai_idev, FKIOCTL, kcred, &junk)) != 0))
		return (rv);

	/* apply settings to the output device */
	if ((lxa_state->lxas_odev_lh != NULL) &&
	    ((rv = ldi_ioctl(lxa_state->lxas_odev_lh, cmd,
	    (intptr_t)&ai_odev, FKIOCTL, kcred, &junk)) != 0))
		return (rv);

	/*
	 * a AUDIO_SETINFO call performs an implicit AUDIO_GETINFO to
	 * return values (see the coments in audioio.h.) so we need
	 * to combine the values returned from the input and output
	 * device back into the users buffer.
	 */
	lxa_audio_info_merge(lxa_state, &ai_idev, &ai_odev, &ai);

	/* copyout the results */
	if (ddi_copyout(&ai, (void *)arg, sizeof (ai), mode) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
lxa_audio_getinfo(lxa_state_t *lxa_state, intptr_t arg, int mode)
{
	audio_info_t	ai, ai_idev, ai_odev;
	int		rv, junk;

	/* get the settings from the input device */
	if ((lxa_state->lxas_idev_lh != NULL) &&
	    ((rv = ldi_ioctl(lxa_state->lxas_idev_lh, AUDIO_GETINFO,
	    (intptr_t)&ai_idev, FKIOCTL, kcred, &junk)) != 0))
		return (rv);

	/* get the settings from the output device */
	if ((lxa_state->lxas_odev_lh != NULL) &&
	    ((rv = ldi_ioctl(lxa_state->lxas_odev_lh, AUDIO_GETINFO,
	    (intptr_t)&ai_odev, FKIOCTL, kcred, &junk)) != 0))
		return (rv);

	/*
	 * we need to combine the values returned from the input
	 * and output device back into a single user buffer.
	 */
	lxa_audio_info_merge(lxa_state, &ai_idev, &ai_odev, &ai);

	/* copyout the results */
	if (ddi_copyout(&ai, (void *)arg, sizeof (ai), mode) != 0)
		return (EFAULT);

	return (0);
}

static int
lxa_mixer_ai_from_lh(ldi_handle_t lh, audio_info_t *ai)
{
	am_control_t	*actl;
	int		rv, ch_count, junk;

	ASSERT((lh != NULL) && (ai != NULL));

	/* get the number of channels for the underlying device */
	if ((rv = ldi_ioctl(lh, AUDIO_GET_NUM_CHS,
	    (intptr_t)&ch_count, FKIOCTL, kcred, &junk)) != 0)
		return (rv);

	/* allocate the am_control_t structure */
	actl = kmem_alloc(AUDIO_MIXER_CTL_STRUCT_SIZE(ch_count), KM_SLEEP);

	/* get the device state and channel state */
	if ((rv = ldi_ioctl(lh, AUDIO_MIXERCTL_GETINFO,
	    (intptr_t)actl, FKIOCTL, kcred, &junk)) != 0) {
		kmem_free(actl, AUDIO_MIXER_CTL_STRUCT_SIZE(ch_count));
		return (rv);
	}

	/* return the audio_info structure */
	*ai = actl->dev_info;
	kmem_free(actl, AUDIO_MIXER_CTL_STRUCT_SIZE(ch_count));
	return (0);
}

static int
lxa_mixer_get_ai(lxa_state_t *lxa_state, audio_info_t *ai)
{
	audio_info_t	ai_idev, ai_odev;
	int		rv;

	/* if there is no input device, query the output device */
	if (lxa_state->lxas_idev_lh == NULL)
		return (lxa_mixer_ai_from_lh(lxa_state->lxas_odev_lh, ai));

	/* if there is no ouput device, query the intput device */
	if (lxa_state->lxas_odev_lh == NULL)
		return (lxa_mixer_ai_from_lh(lxa_state->lxas_idev_lh, ai));

	/*
	 * now get the audio_info and channel information for the
	 * underlying output device.
	 */
	if ((rv = lxa_mixer_ai_from_lh(lxa_state->lxas_idev_lh,
	    &ai_idev)) != 0)
		return (rv);
	if ((rv = lxa_mixer_ai_from_lh(lxa_state->lxas_odev_lh,
	    &ai_odev)) != 0)
		return (rv);

	/* now merge the audio_info structures */
	lxa_audio_info_merge(lxa_state, &ai_idev, &ai_odev, ai);
	return (0);
}

static int
lxa_mixer_get_common(lxa_state_t *lxa_state, int cmd, intptr_t arg, int mode)
{
	lxa_mixer_levels_t	lxa_ml;
	audio_info_t		ai;
	int			rv;

	ASSERT(lxa_state->lxas_type == LXA_TYPE_AUDIOCTL);

	if ((rv = lxa_mixer_get_ai(lxa_state, &ai)) != 0)
		return (rv);

	switch (cmd) {
	case LXA_IOC_MIXER_GET_VOL:
		lxa_ml.lxa_ml_gain = ai.play.gain;
		lxa_ml.lxa_ml_balance = ai.play.balance;
		break;
	case LXA_IOC_MIXER_GET_MIC:
		lxa_ml.lxa_ml_gain = ai.record.gain;
		lxa_ml.lxa_ml_balance = ai.record.balance;
		break;
	}

	if (ddi_copyout(&lxa_ml, (void *)arg, sizeof (lxa_ml), mode) != 0)
		return (EFAULT);
	return (0);
}

static int
lxa_mixer_set_common(lxa_state_t *lxa_state, int cmd, intptr_t arg, int mode)
{
	lxa_mixer_levels_t	lxa_ml;
	audio_info_t		ai;

	ASSERT(lxa_state->lxas_type == LXA_TYPE_AUDIOCTL);

	/* get the new mixer settings */
	if (ddi_copyin((void *)arg, &lxa_ml, sizeof (lxa_ml), mode) != 0)
		return (EFAULT);

	/* sanity check the mixer settings */
	if (!LXA_MIXER_LEVELS_OK(&lxa_ml))
		return (EINVAL);

	/* initialize an audio_info struct with the new settings */
	AUDIO_INITINFO(&ai);
	switch (cmd) {
	case LXA_IOC_MIXER_SET_VOL:
		ai.play.gain = lxa_ml.lxa_ml_gain;
		ai.play.balance = lxa_ml.lxa_ml_balance;
		break;
	case LXA_IOC_MIXER_SET_MIC:
		ai.record.gain = lxa_ml.lxa_ml_gain;
		ai.record.balance = lxa_ml.lxa_ml_balance;
		break;
	}

	/*
	 * we're going to cheat here.  normally the
	 * MIXERCTL_SETINFO ioctl take am_control_t and the
	 * AUDIO_SETINFO takes an audio_info_t.  as it turns
	 * out the first element in a am_control_t is an
	 * audio_info_t.  also, the rest of the am_control_t
	 * structure is normally ignored for a MIXERCTL_SETINFO
	 * ioctl.  so here we'll try to fall back to the code
	 * that handles AUDIO_SETINFO ioctls.
	 */
	return (lxa_audio_setinfo(lxa_state, AUDIO_MIXERCTL_SETINFO,
	    (intptr_t)&ai, FKIOCTL));
}

static int
lxa_mixer_get_pcm(lxa_state_t *lxa_state, intptr_t arg, int mode)
{
	ASSERT(lxa_state->lxas_type == LXA_TYPE_AUDIOCTL);

	/* simply return the cached pcm mixer settings */
	mutex_enter(&lxa_lock);
	if (ddi_copyout(&lxa_state->lxas_zs->lxa_zs_pcm_levels, (void *)arg,
	    sizeof (lxa_state->lxas_zs->lxa_zs_pcm_levels), mode) != 0) {
		mutex_exit(&lxa_lock);
		return (EFAULT);
	}
	mutex_exit(&lxa_lock);
	return (0);
}

static int
lxa_mixer_set_pcm(lxa_state_t *lxa_state, intptr_t arg, int mode)
{
	lxa_mixer_levels_t	lxa_ml;
	int			rv;

	ASSERT(lxa_state->lxas_type == LXA_TYPE_AUDIOCTL);

	/* get the new mixer settings */
	if (ddi_copyin((void *)arg, &lxa_ml, sizeof (lxa_ml), mode) != 0)
		return (EFAULT);

	/* sanity check the mixer settings */
	if (!LXA_MIXER_LEVELS_OK(&lxa_ml))
		return (EINVAL);

	mutex_enter(&lxa_lock);

	/* if there is an active output channel, update it */
	if (lxa_state->lxas_zs->lxa_zs_ostate != NULL) {
		audio_info_t	ai;

		/* initialize an audio_info struct with the new settings */
		AUDIO_INITINFO(&ai);
		ai.play.gain = lxa_ml.lxa_ml_gain;
		ai.play.balance = lxa_ml.lxa_ml_balance;

		if ((rv = lxa_audio_setinfo(lxa_state->lxas_zs->lxa_zs_ostate,
		    AUDIO_SETINFO, (intptr_t)&ai, FKIOCTL)) != 0) {
			mutex_exit(&lxa_lock);
			return (rv);
		}
	}

	/* update the cached mixer settings */
	lxa_state->lxas_zs->lxa_zs_pcm_levels = lxa_ml;

	mutex_exit(&lxa_lock);
	return (0);
}

static int
lxa_zone_reg(intptr_t arg, int mode)
{
	lxa_zone_reg_t	lxa_zr;
	lxa_zstate_t	*lxa_zs = NULL;
	char		*idev_name = NULL, *odev_name = NULL, *pval = NULL;
	int		i, junk;

	if (ddi_copyin((void *)arg, &lxa_zr, sizeof (lxa_zr), mode) != 0)
		return (EFAULT);

	/* make sure that zone_name is a valid string */
	for (i = 0; i < sizeof (lxa_zr.lxa_zr_zone_name); i++)
		if (lxa_zr.lxa_zr_zone_name[i] == '\0')
			break;
	if (i == sizeof (lxa_zr.lxa_zr_zone_name))
		return (EINVAL);

	/* make sure that inputdev is a valid string */
	for (i = 0; i < sizeof (lxa_zr.lxa_zr_inputdev); i++)
		if (lxa_zr.lxa_zr_inputdev[i] == '\0')
			break;
	if (i == sizeof (lxa_zr.lxa_zr_inputdev))
		return (EINVAL);

	/* make sure it's a valid inputdev property value */
	if (lxa_devprop_verify(lxa_zr.lxa_zr_inputdev) != 0)
		return (EINVAL);

	/* make sure that outputdev is a valid string */
	for (i = 0; i < sizeof (lxa_zr.lxa_zr_outputdev); i++)
		if (lxa_zr.lxa_zr_outputdev[i] == '\0')
			break;
	if (i == sizeof (lxa_zr.lxa_zr_outputdev))
		return (EINVAL);

	/* make sure it's a valid outputdev property value */
	if (lxa_devprop_verify(lxa_zr.lxa_zr_outputdev) != 0)
		return (EINVAL);

	/* get the property names */
	idev_name = lxa_devprop_name(lxa_zr.lxa_zr_zone_name,
	    LXA_PROP_INPUTDEV);
	odev_name = lxa_devprop_name(lxa_zr.lxa_zr_zone_name,
	    LXA_PROP_OUTPUTDEV);

	/*
	 * allocate and initialize a zone state structure
	 * since the audio device can't possibly be opened yet
	 * (since we're setting it up now and the zone isn't booted
	 * yet) assign some some resonable default pcm channel settings.
	 * also, default to one mixer channel.
	 */
	lxa_zs = kmem_zalloc(sizeof (*lxa_zs), KM_SLEEP);
	lxa_zs->lxa_zs_zonename = strdup(lxa_zr.lxa_zr_zone_name);
	lxa_zs->lxa_zs_pcm_levels.lxa_ml_gain = AUDIO_MID_GAIN;
	lxa_zs->lxa_zs_pcm_levels.lxa_ml_balance = AUDIO_MID_BALANCE;

	mutex_enter(&lxa_lock);

	/*
	 * make sure this zone isn't already registered
	 * a zone is registered with properties for that zone exist
	 * or there is a zone state structure for that zone
	 */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, lxa_dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    idev_name, &pval) == DDI_PROP_SUCCESS) {
		goto err_unlock;
	}
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, lxa_dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    odev_name, &pval) == DDI_PROP_SUCCESS) {
		goto err_unlock;
	}
	if (mod_hash_find(lxa_zstate_hash,
	    (mod_hash_key_t)lxa_zs->lxa_zs_zonename,
	    (mod_hash_val_t *)&junk) == 0)
		goto err_unlock;

	/*
	 * create the new properties and insert the zone state structure
	 * into the global hash
	 */
	if (ddi_prop_update_string(DDI_DEV_T_NONE, lxa_dip,
	    idev_name, lxa_zr.lxa_zr_inputdev) != DDI_PROP_SUCCESS)
		goto err_prop_remove;
	if (ddi_prop_update_string(DDI_DEV_T_NONE, lxa_dip,
	    odev_name, lxa_zr.lxa_zr_outputdev) != DDI_PROP_SUCCESS)
		goto err_prop_remove;
	if (mod_hash_insert(lxa_zstate_hash,
	    (mod_hash_key_t)lxa_zs->lxa_zs_zonename,
	    (mod_hash_val_t)lxa_zs) != 0)
		goto err_prop_remove;

	/* success! */
	lxa_registered_zones++;
	mutex_exit(&lxa_lock);

	/* cleanup */
	strfree(idev_name);
	strfree(odev_name);
	return (0);

err_prop_remove:
	(void) ddi_prop_remove(DDI_DEV_T_NONE, lxa_dip, idev_name);
	(void) ddi_prop_remove(DDI_DEV_T_NONE, lxa_dip, odev_name);

err_unlock:
	mutex_exit(&lxa_lock);

err:
	if (lxa_zs != NULL) {
		strfree(lxa_zs->lxa_zs_zonename);
		kmem_free(lxa_zs, sizeof (*lxa_zs));
	}
	if (pval != NULL)
		ddi_prop_free(pval);
	if (idev_name != NULL)
		strfree(idev_name);
	if (odev_name != NULL)
		strfree(odev_name);
	return (EIO);
}

static int
lxa_zone_unreg(intptr_t arg, int mode)
{
	lxa_zone_reg_t	lxa_zr;
	lxa_zstate_t	*lxa_zs = NULL;
	char		*idev_name = NULL, *odev_name = NULL, *pval = NULL;
	int		rv, i;

	if (ddi_copyin((void *)arg, &lxa_zr, sizeof (lxa_zr), mode) != 0)
		return (EFAULT);

	/* make sure that zone_name is a valid string */
	for (i = 0; i < sizeof (lxa_zr.lxa_zr_zone_name); i++)
		if (lxa_zr.lxa_zr_zone_name[i] == '\0')
			break;
	if (i == sizeof (lxa_zr.lxa_zr_zone_name))
		return (EINVAL);

	/* get the property names */
	idev_name = lxa_devprop_name(lxa_zr.lxa_zr_zone_name,
	    LXA_PROP_INPUTDEV);
	odev_name = lxa_devprop_name(lxa_zr.lxa_zr_zone_name,
	    LXA_PROP_OUTPUTDEV);

	mutex_enter(&lxa_lock);

	if (lxa_registered_zones <= 0) {
		rv = ENOENT;
		goto err_unlock;
	}

	/* make sure this zone is actually registered */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, lxa_dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    idev_name, &pval) != DDI_PROP_SUCCESS) {
		rv = ENOENT;
		goto err_unlock;
	}
	ddi_prop_free(pval);
	pval = NULL;
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, lxa_dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    odev_name, &pval) != DDI_PROP_SUCCESS) {
		rv = ENOENT;
		goto err_unlock;
	}
	ddi_prop_free(pval);
	pval = NULL;
	if (mod_hash_find(lxa_zstate_hash,
	    (mod_hash_key_t)lxa_zr.lxa_zr_zone_name,
	    (mod_hash_val_t *)&lxa_zs) != 0) {
		rv = ENOENT;
		goto err_unlock;
	}
	ASSERT(strcmp(lxa_zr.lxa_zr_zone_name, lxa_zs->lxa_zs_zonename) == 0);

	/*
	 * if the audio device is currently in use then refuse to
	 * unregister the zone
	 */
	if ((lxa_zs->lxa_zs_ostate != NULL) ||
	    (lxa_zs->lxa_zs_ostate != NULL)) {
		rv = EBUSY;
		goto err_unlock;
	}

	/* success! cleanup zone config state */
	(void) ddi_prop_remove(DDI_DEV_T_NONE, lxa_dip, idev_name);
	(void) ddi_prop_remove(DDI_DEV_T_NONE, lxa_dip, odev_name);

	/*
	 * note, the action of removing the zone state structure from the
	 * hash will automatically free lxa_zs->lxa_zs_zonename.
	 *
	 * the reason for this is that we used lxa_zs->lxa_zs_zonename
	 * as the hash key and by default mod_hash_create_strhash() uses
	 * mod_hash_strkey_dtor() as a the hash key destructor.  (which
	 * free's the key for us.
	 */
	(void) mod_hash_remove(lxa_zstate_hash,
	    (mod_hash_key_t)lxa_zr.lxa_zr_zone_name,
	    (mod_hash_val_t *)&lxa_zs);
	lxa_registered_zones--;
	mutex_exit(&lxa_lock);

	/* cleanup */
	kmem_free(lxa_zs, sizeof (*lxa_zs));
	strfree(idev_name);
	strfree(odev_name);
	return (0);

err_unlock:
	mutex_exit(&lxa_lock);

err:
	if (pval != NULL)
		ddi_prop_free(pval);
	if (idev_name != NULL)
		strfree(idev_name);
	if (odev_name != NULL)
		strfree(odev_name);
	return (rv);
}

static int
lxa_ioctl_devctl(int cmd, intptr_t arg, int mode)
{
	/* devctl ioctls are only allowed from the global zone */
	ASSERT(getzoneid() == 0);
	if (getzoneid() != 0)
		return (EINVAL);

	switch (cmd) {
	case LXA_IOC_ZONE_REG:
		return (lxa_zone_reg(arg, mode));
	case LXA_IOC_ZONE_UNREG:
		return (lxa_zone_unreg(arg, mode));
	}

	return (EINVAL);
}

static int
/*ARGSUSED*/
lxa_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	lxa_dev_type_t	open_type = LXA_TYPE_INVALID;
	lxa_zstate_t	*lxa_zs;
	lxa_state_t	*lxa_state;
	minor_t		minor;
	int		rv;

	if (getminor(*devp) == LXA_MINORNUM_DEVCTL) {
		/*
		 * this is a devctl node, it exists to administer this
		 * pseudo driver so it doesn't actually need access to
		 * any underlying audio devices.  hence there is nothing
		 * really to do here.  course, this driver should
		 * only be administered from the global zone.
		 */
		ASSERT(getzoneid() == 0);
		if (getzoneid() != 0)
			return (EINVAL);
		return (0);
	}

	/* lookup the zone state structure */
	if (mod_hash_find(lxa_zstate_hash, (mod_hash_key_t)getzonename(),
	    (mod_hash_val_t *)&lxa_zs) != 0) {
		return (EIO);
	}

	/* determine what type of device was opened */
	switch (getminor(*devp)) {
	case LXA_MINORNUM_DSP:
		open_type = LXA_TYPE_AUDIO;
		break;
	case LXA_MINORNUM_MIXER:
		open_type = LXA_TYPE_AUDIOCTL;
		break;
	default:
		return (EINVAL);
	}
	ASSERT(open_type != LXA_TYPE_INVALID);

	/* all other opens are clone opens so get a new minor node */
	minor = id_alloc(lxa_minor_id);

	/* allocate and initialize the new lxa_state structure */
	lxa_state = kmem_zalloc(sizeof (*lxa_state), KM_SLEEP);
	lxa_state->lxas_zs = lxa_zs;
	lxa_state->lxas_dev_old = *devp;
	lxa_state->lxas_dev_new = makedevice(getmajor(*devp), minor);
	lxa_state->lxas_flags = flags;
	lxa_state->lxas_type = open_type;

	/* initialize the input and output device */
	if (((rv = lxa_dev_open(lxa_state)) != 0) ||
	    ((rv = lxa_dev_getfeatures(lxa_state)) != 0)) {
		lxa_state_close(lxa_state);
		return (rv);
	}

	/*
	 * save this audio statue structure into a hash indexed
	 * by it's minor device number.  (this will provide a convient
	 * way to lookup the state structure on future operations.)
	 */
	if (mod_hash_insert(lxa_state_hash, (mod_hash_key_t)(uintptr_t)minor,
	    (mod_hash_val_t)lxa_state) != 0) {
		lxa_state_close(lxa_state);
		return (EIO);
	}

	mutex_enter(&lxa_lock);

	/* apply the currently cached zone PCM mixer levels */
	if ((lxa_state->lxas_type == LXA_TYPE_AUDIO) &&
	    (lxa_state->lxas_odev_lh != NULL)) {
		audio_info_t ai;

		AUDIO_INITINFO(&ai);
		ai.play.gain = lxa_zs->lxa_zs_pcm_levels.lxa_ml_gain;
		ai.play.balance = lxa_zs->lxa_zs_pcm_levels.lxa_ml_balance;

		if ((rv = lxa_audio_setinfo(lxa_state,
		    AUDIO_SETINFO, (intptr_t)&ai, FKIOCTL)) != 0) {
			mutex_exit(&lxa_lock);
			lxa_state_close(lxa_state);
			return (rv);
		}
	}

	/*
	 * we only allow one active open of the input or output device.
	 * check here for duplicate opens
	 */
	if (lxa_state->lxas_type == LXA_TYPE_AUDIO) {
		if ((lxa_state->lxas_idev_lh != NULL) &&
		    (lxa_zs->lxa_zs_istate != NULL)) {
			mutex_exit(&lxa_lock);
			lxa_state_close(lxa_state);
			return (EBUSY);
		}
		if ((lxa_state->lxas_odev_lh != NULL) &&
		    (lxa_zs->lxa_zs_ostate != NULL)) {
			mutex_exit(&lxa_lock);
			lxa_state_close(lxa_state);
			return (EBUSY);
		}

		/* not a duplicate open, update the global zone state */
		if (lxa_state->lxas_idev_lh != NULL)
			lxa_zs->lxa_zs_istate = lxa_state;
		if (lxa_state->lxas_odev_lh != NULL)
			lxa_zs->lxa_zs_ostate = lxa_state;
	}
	mutex_exit(&lxa_lock);

	/* make sure to return our newly allocated dev_t */
	*devp = lxa_state->lxas_dev_new;
	return (0);
}

static int
/*ARGSUSED*/
lxa_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	lxa_state_t	*lxa_state;
	minor_t		minor = getminor(dev);

	/* handle devctl minor nodes (these nodes don't have a handle */
	if (getminor(dev) == LXA_MINORNUM_DEVCTL)
		return (0);

	/* get the handle for this device */
	if (mod_hash_find(lxa_state_hash, (mod_hash_key_t)(uintptr_t)minor,
	    (mod_hash_val_t *)&lxa_state) != 0)
		return (EINVAL);

	lxa_state_close(lxa_state);
	return (0);
}

static int
/*ARGSUSED*/
lxa_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	lxa_state_t	*lxa_state;
	minor_t		minor = getminor(dev);

	/* get the handle for this device */
	if (mod_hash_find(lxa_state_hash, (mod_hash_key_t)(uintptr_t)minor,
	    (mod_hash_val_t *)&lxa_state) != 0)
		return (EINVAL);

	/*
	 * if a process has mmaped this device then we don't allow
	 * any more reads or writes to the device
	 */
	if (lxa_state->lxas_umem_cookie != NULL)
		return (EIO);

	/* we can't do a read if there is no input device */
	if (lxa_state->lxas_idev_lh == NULL)
		return (EBADF);

	/* pass the request on */
	return (ldi_read(lxa_state->lxas_idev_lh, uiop, kcred));
}

static int
/*ARGSUSED*/
lxa_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	lxa_state_t	*lxa_state;
	minor_t		minor = getminor(dev);

	/* get the handle for this device */
	if (mod_hash_find(lxa_state_hash, (mod_hash_key_t)(uintptr_t)minor,
	    (mod_hash_val_t *)&lxa_state) != 0)
		return (EINVAL);

	/*
	 * if a process has mmaped this device then we don't allow
	 * any more reads or writes to the device
	 */
	if (lxa_state->lxas_umem_cookie != NULL)
		return (EIO);

	/* we can't do a write if there is no output device */
	if (lxa_state->lxas_odev_lh == NULL)
		return (EBADF);

	/* pass the request on */
	return (ldi_write(lxa_state->lxas_odev_lh, uiop, kcred));
}

static int
/*ARGSUSED*/
lxa_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	lxa_state_t	*lxa_state;
	minor_t		minor = getminor(dev);

	/* handle devctl minor nodes (these nodes don't have a handle */
	if (getminor(dev) == LXA_MINORNUM_DEVCTL)
		return (lxa_ioctl_devctl(cmd, arg, mode));

	/* get the handle for this device */
	if (mod_hash_find(lxa_state_hash, (mod_hash_key_t)(uintptr_t)minor,
	    (mod_hash_val_t *)&lxa_state) != 0)
		return (EINVAL);

	ASSERT((lxa_state->lxas_type == LXA_TYPE_AUDIO) ||
	    (lxa_state->lxas_type == LXA_TYPE_AUDIOCTL));

	switch (cmd) {
	case LXA_IOC_GETMINORNUM:
		{
			int minornum = getminor(lxa_state->lxas_dev_old);
			if (ddi_copyout(&minornum, (void *)arg,
			    sizeof (minornum), mode) != 0)
				return (EFAULT);
		}
		return (0);
	}

	if (lxa_state->lxas_type == LXA_TYPE_AUDIO) {
		/* deal with native ioctl */
		switch (cmd) {
		case LXA_IOC_MMAP_OUTPUT:
			return (lxa_ioc_mmap_output(lxa_state, arg, mode));
		case LXA_IOC_MMAP_PTR:
			return (lxa_ioc_mmap_ptr(lxa_state, arg, mode));
		case LXA_IOC_GET_FRAG_INFO:
			return (lxa_ioc_get_frag_info(lxa_state, arg, mode));
		case LXA_IOC_SET_FRAG_INFO:
			return (lxa_ioc_set_frag_info(lxa_state, arg, mode));
		}

		/* deal with layered ioctls */
		switch (cmd) {
		case AUDIO_DRAIN:
			return (lxa_audio_drain(lxa_state));
		case AUDIO_SETINFO:
			return (lxa_audio_setinfo(lxa_state,
			    AUDIO_SETINFO, arg, mode));
		case AUDIO_GETINFO:
			return (lxa_audio_getinfo(lxa_state, arg, mode));
		}
	}

	if (lxa_state->lxas_type == LXA_TYPE_AUDIOCTL) {
		/* deal with native ioctl */
		switch (cmd) {
		case LXA_IOC_MIXER_GET_VOL:
			return (lxa_mixer_get_common(lxa_state,
			    cmd, arg, mode));
		case LXA_IOC_MIXER_SET_VOL:
			return (lxa_mixer_set_common(lxa_state,
			    cmd, arg, mode));
		case LXA_IOC_MIXER_GET_MIC:
			return (lxa_mixer_get_common(lxa_state,
			    cmd, arg, mode));
		case LXA_IOC_MIXER_SET_MIC:
			return (lxa_mixer_set_common(lxa_state,
			    cmd, arg, mode));
		case LXA_IOC_MIXER_GET_PCM:
			return (lxa_mixer_get_pcm(lxa_state, arg, mode));
		case LXA_IOC_MIXER_SET_PCM:
			return (lxa_mixer_set_pcm(lxa_state, arg, mode));
		}

	}

	return (EINVAL);
}

static int
/*ARGSUSED*/
lxa_devmap(dev_t dev, devmap_cookie_t dhp,
    offset_t off, size_t len, size_t *maplen, uint_t model)
{
	lxa_state_t		*lxa_state;
	minor_t			minor = getminor(dev);
	ddi_umem_cookie_t	umem_cookie;
	void			*umem_ptr;
	int			rv;

	/* get the handle for this device */
	if (mod_hash_find(lxa_state_hash, (mod_hash_key_t)(uintptr_t)minor,
	    (mod_hash_val_t *)&lxa_state) != 0)
		return (EINVAL);

	/* we only support mmaping of audio devices */
	if (lxa_state->lxas_type != LXA_TYPE_AUDIO)
		return (EINVAL);

	/* we only support output via mmap */
	if ((lxa_state->lxas_flags & FWRITE) == 0)
		return (EINVAL);

	/* sanity check the amount of memory the user is allocating */
	if ((len == 0) ||
	    (len > LXA_OSS_FRAG_MEM) ||
	    ((len % lxa_state->lxas_frag_size) != 0))
		return (EINVAL);

	/* allocate and clear memory to mmap */
	umem_ptr = ddi_umem_alloc(len, DDI_UMEM_NOSLEEP, &umem_cookie);
	if (umem_ptr == NULL)
		return (ENOMEM);
	bzero(umem_ptr, len);

	/* setup the memory mappings */
	rv = devmap_umem_setup(dhp, lxa_dip, NULL, umem_cookie, 0, len,
	    PROT_USER | PROT_READ | PROT_WRITE, 0, NULL);
	if (rv != 0) {
		ddi_umem_free(umem_cookie);
		return (EIO);
	}

	mutex_enter(&lxa_lock);

	/* we only support one mmap per open */
	if (lxa_state->lxas_umem_cookie != NULL) {
		ASSERT(lxa_state->lxas_umem_ptr != NULL);
		mutex_exit(&lxa_lock);
		ddi_umem_free(umem_cookie);
		return (EBUSY);
	}
	ASSERT(lxa_state->lxas_umem_ptr == NULL);

	*maplen = len;
	lxa_state->lxas_umem_len = len;
	lxa_state->lxas_umem_ptr = umem_ptr;
	lxa_state->lxas_umem_cookie = umem_cookie;
	mutex_exit(&lxa_lock);
	return (0);
}

static int
/*ARGSUSED*/
lxa_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int	instance = ddi_get_instance(dip);

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	ASSERT(instance == 0);
	if (instance != 0)
		return (DDI_FAILURE);

	lxa_dip = dip;
	mutex_init(&lxa_lock, NULL, MUTEX_DEFAULT, NULL);

	/* create our minor nodes */
	if (ddi_create_minor_node(dip, LXA_MINORNAME_DEVCTL, S_IFCHR,
	    LXA_MINORNUM_DEVCTL, DDI_PSEUDO, 0) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(dip, LXA_MINORNAME_DSP, S_IFCHR,
	    LXA_MINORNUM_DSP, DDI_PSEUDO, 0) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(dip, LXA_MINORNAME_MIXER, S_IFCHR,
	    LXA_MINORNUM_MIXER, DDI_PSEUDO, 0) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/* allocate our data structures */
	lxa_minor_id = id_space_create("lxa_minor_id",
	    LXA_MINORNUM_COUNT, LX_AUDIO_MAX_OPENS);
	lxa_state_hash = mod_hash_create_idhash("lxa_state_hash",
	    lxa_state_hash_size, mod_hash_null_valdtor);
	lxa_zstate_hash = mod_hash_create_strhash("lxa_zstate_hash",
	    lxa_zstate_hash_size, mod_hash_null_valdtor);

	return (DDI_SUCCESS);
}

static int
/*ARGSUSED*/
lxa_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	ASSERT(!MUTEX_HELD(&lxa_lock));
	if (lxa_registered_zones > 0)
		return (DDI_FAILURE);

	mod_hash_destroy_idhash(lxa_state_hash);
	mod_hash_destroy_idhash(lxa_zstate_hash);
	id_space_destroy(lxa_minor_id);
	lxa_state_hash = NULL;
	lxa_dip = NULL;

	return (DDI_SUCCESS);
}

static int
/*ARGSUSED*/
lxa_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **resultp)
{
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*resultp = lxa_dip;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)0;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

/*
 * Driver flags
 */
static struct cb_ops lxa_cb_ops = {
	lxa_open,		/* open */
	lxa_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	lxa_read,		/* read */
	lxa_write,		/* write */
	lxa_ioctl,		/* ioctl */
	lxa_devmap,		/* devmap */
	nodev,			/* mmap */
	ddi_devmap_segmap,	/* segmap */
	nochpoll,		/* chpoll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* cb_str */
	D_NEW | D_MP | D_DEVMAP,
	CB_REV,
	NULL,
	NULL
};

static struct dev_ops lxa_ops = {
	DEVO_REV,
	0,
	lxa_getinfo,
	nulldev,
	nulldev,
	lxa_attach,
	lxa_detach,
	nodev,
	&lxa_cb_ops,
	NULL,
	NULL,
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,		/* type of module */
	"linux audio driver",	/* description of module */
	&lxa_ops		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

/*
 * standard module entry points
 */
int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
