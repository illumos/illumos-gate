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
 * Copyright 1989-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains routines to read and write the audio device state.
 */

#include <errno.h>
#include <stropts.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <libaudio_impl.h>
#include <audio_errno.h>
#include <audio_hdr.h>
#include <audio_device.h>


/*
 * Get device information structure.
 */
int
audio_getinfo(int fd, Audio_info *ip)
{
	if (ioctl(fd, AUDIO_GETINFO, (char *)ip) < 0) {
		return (AUDIO_UNIXERROR);
	} else {
		return (AUDIO_SUCCESS);
	}
}

/*
 * Set device information structure.
 * The calling routine should use AUDIO_INITINFO prior to setting new values.
 */
int
audio_setinfo(int fd, Audio_info *ip)
{
	if (ioctl(fd, AUDIO_SETINFO, (char *)ip) < 0) {
		return (AUDIO_UNIXERROR);
	} else {
		return (AUDIO_SUCCESS);
	}
}

/*
 * Return an Audio_hdr corresponding to the encoding configuration
 * of the audio device on 'fd'.
 */
int
audio__setplayhdr(int fd, Audio_hdr *hdrp, unsigned int which)
{
	Audio_hdr		thdr;
	Audio_info		info;
	struct audio_prinfo	*prinfo;
	int			err;

	if (which & AUDIO__PLAY)
		prinfo = &info.play;
	else if (which & AUDIO__RECORD)
		prinfo = &info.record;
	else
		return (AUDIO_ERR_BADARG);

	if (which & AUDIO__SET) {
		thdr = *hdrp;			/* save original hdr */
		AUDIO_INITINFO(&info);
		prinfo->sample_rate = hdrp->sample_rate;
		prinfo->channels = hdrp->channels;
		prinfo->encoding = hdrp->encoding;
		prinfo->precision = hdrp->bytes_per_unit * 8;
		err = audio_setinfo(fd, &info);
	} else {
		err = audio_getinfo(fd, &info);
	}

	/* Decode back into the header structure */
	/* since the I_SMSG is set, upon completion of updating 	*/
	/* the format, the driver sends the msg  so the 		*/
	/* system call is interrupted.  For now, just ignore this 	*/
	if ((err == AUDIO_SUCCESS) || (errno == EINTR)) {
		hdrp->sample_rate = prinfo->sample_rate;
		hdrp->channels = prinfo->channels;
		hdrp->data_size = AUDIO_UNKNOWN_SIZE;
		hdrp->encoding = prinfo->encoding;
		switch (hdrp->encoding) {
		case AUDIO_ENCODING_ULAW:
		case AUDIO_ENCODING_ALAW:
		case AUDIO_ENCODING_LINEAR:
		case AUDIO_ENCODING_LINEAR8:
		case AUDIO_ENCODING_FLOAT:
			hdrp->bytes_per_unit = prinfo->precision / 8;
			hdrp->samples_per_unit = 1;
			break;
		default:
			return (AUDIO_ERR_ENCODING);
		}
		if (which & AUDIO__SET) {
			/* Check to see if *all* changes took effect */
			if (audio_cmp_hdr(hdrp, &thdr) != 0)
				return (AUDIO_ERR_NOEFFECT);
		}
	}
	return (err);
}


/*
 * Attempt to configure the audio device to match a particular encoding.
 */

/*
 * Set and/or set individual state values.
 * This routine is generally invoked by using the audio_set_*()
 * and audio_get_*() macros.
 * The 'valp' argument is always a pointer to an unsigned int.
 * Conversions to/from (unsigned char) flags are taken care of.
 */
int
audio__setval(int fd, unsigned int *valp, unsigned int which)
{
	Audio_info		info;
	struct audio_prinfo	*prinfo;
	int			err;
	unsigned		*up;
	unsigned char		*cp;

	/* Set a pointer to the value of interest */
	if (which & AUDIO__PLAY)
		prinfo = &info.play;
	else if (which & AUDIO__RECORD)
		prinfo = &info.record;
	else if ((which & AUDIO__SETVAL_MASK) != AUDIO__MONGAIN)
		return (AUDIO_ERR_BADARG);

	up = NULL;
	switch (which & AUDIO__SETVAL_MASK) {
	case AUDIO__PORT:
		up = &prinfo->port; break;
	case AUDIO__SAMPLES:
		up = &prinfo->samples; break;
	case AUDIO__ERROR:
		cp = &prinfo->error; break;
	case AUDIO__EOF:
		up = &prinfo->eof; break;
	case AUDIO__OPEN:
		cp = &prinfo->open; break;
	case AUDIO__ACTIVE:
		cp = &prinfo->active; break;
	case AUDIO__WAITING:
		cp = &prinfo->waiting; break;
	case AUDIO__GAIN:
		up = &prinfo->gain; break;
	case AUDIO__MONGAIN:
		up = &info.monitor_gain; break;
	case AUDIO__BALANCE:
		cp = &prinfo->balance; break;
	default:
		return (AUDIO_ERR_BADARG);
	}

	if (which & AUDIO__SET) {
		/* Init so that only the value of interest is changed */
		AUDIO_INITINFO(&info);
		if (up != NULL) {
			*up = *valp;
		} else {
			*cp = (unsigned char) *valp;
		}
		err = audio_setinfo(fd, &info);
	} else {
		err = audio_getinfo(fd, &info);
	}
	if (err == AUDIO_SUCCESS) {
		if (up != NULL)
			*valp = *up;
		else
			*valp = (unsigned)*cp;
	}
	return (err);
}

/*
 * Get/set gain value.
 * NOTE: legal values are floating-point double 0. - 1.
 */
int
audio__setgain(int fd, double *valp, unsigned int which)
{
	int		err;
	unsigned	x;

	if (which & AUDIO__SET) {
		if ((*valp < 0.) || (*valp > 1.))
			return (AUDIO_ERR_BADARG);

		/* Map value into legal range */
		x = ((unsigned)(*valp * (AUDIO_MAX_GAIN - AUDIO_MIN_GAIN))) +
		    AUDIO_MIN_GAIN;
	}

	/* Get or set the new value */
	err = audio__setval(fd, &x, which);
	if (err == AUDIO_SUCCESS) {
		/* Map value back to double */
		*valp = ((double)(x - AUDIO_MIN_GAIN) /
		    (AUDIO_MAX_GAIN - AUDIO_MIN_GAIN));
	}
	return (err);
}

/*
 * Set Pause/resume flags.
 * Can set play and record individually or together.
 */
int
audio__setpause(int fd, unsigned int which)
{
	Audio_info	info;
	int		err;
	unsigned char	x;

	AUDIO_INITINFO(&info);

	if ((which & AUDIO__SETVAL_MASK) == AUDIO__PAUSE) {
		x = TRUE;
	} else if ((which & AUDIO__SETVAL_MASK) == AUDIO__RESUME) {
		x = FALSE;
	} else {
		return (AUDIO_ERR_BADARG);
	}

	if (which & AUDIO__PLAY) {
		info.play.pause = x;
	}
	if (which & AUDIO__RECORD) {
		info.record.pause = x;
	}

	/* Set the new value */
	err = audio_setinfo(fd, &info);

	/* Check to see if this took effect */
	if (err == AUDIO_SUCCESS) {
		if (((which & AUDIO__PLAY) && (info.play.pause != x)) ||
		    ((which & AUDIO__RECORD) && (info.record.pause != x)))
			return (AUDIO_ERR_NOEFFECT);
	}
	return (err);
}


/*
 * Flush play and/or record buffers.
 */
int
audio__flush(int fd, unsigned int which)
{
	int		flag;

	flag = (which & AUDIO__PLAY) ? FLUSHW : 0;
	flag |= (which & AUDIO__RECORD) ? FLUSHR : 0;

	return ((ioctl(fd, I_FLUSH, flag) < 0) ?
	    AUDIO_UNIXERROR : AUDIO_SUCCESS);
}


/*
 * Wait synchronously for output buffers to finish playing.
 * If 'sig' is TRUE, signals may interrupt the drain.
 */
int
audio_drain(int fd, int sig)
{
	while (ioctl(fd, AUDIO_DRAIN, 0) < 0) {
		if (errno != EINTR) {
			return (AUDIO_UNIXERROR);
		}

		if (sig) {
			return (AUDIO_ERR_INTERRUPTED);
		}
	}
	return (AUDIO_SUCCESS);
}

/*
 * Write an EOF marker to the output audio stream.
 */
int
audio_play_eof(int fd)
{
	return (write(fd, (char *)NULL, 0) < 0 ?
	    AUDIO_UNIXERROR : AUDIO_SUCCESS);
}
